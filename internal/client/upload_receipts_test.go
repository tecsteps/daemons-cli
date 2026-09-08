package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestUploadReceiptRejectsAmbiguousOrPrivateResponses(t *testing.T) {
	valid := `{"status":"applied","path":"uploads/file","bytes":0,"sha256":"` + strings.Repeat("a", 64) + `"}`
	for _, raw := range []string{valid, `{"status":"not_found"}`, `{"status":"outcome_unknown"}`} {
		if _, err := decodeUploadReceipt([]byte(raw)); err != nil {
			t.Fatal(err)
		}
	}
	for _, raw := range []string{`null`, `{}`, `{"status":"applied"}`, `{"status":"not_found","path":"private"}`,
		`{"status":"not_found","status":"not_found"}`, valid + `{}`, strings.Replace(valid, `"bytes":0`, `"bytes":null`, 1),
		strings.Replace(valid, `"bytes":0`, `"bytes":1073741825`, 1), strings.Replace(valid, "uploads/file", "../private", 1),
		strings.Replace(valid, "uploads/file", "/private", 1), strings.Replace(valid, "uploads/file", "a//b", 1),
		strings.Replace(valid, `"status":"applied"`, `"status":"unknown"`, 1)} {
		if _, err := decodeUploadReceipt([]byte(raw)); err == nil || strings.Contains(err.Error(), "private") {
			t.Fatalf("accepted or disclosed receipt: %v", err)
		}
	}
}

func TestUploadReceiptUsesFreshFileReadTicketWithoutUpload(t *testing.T) {
	const workspace = "11111111-1111-4111-8111-111111111111"
	const operation = "22222222-2222-4222-8222-222222222222"
	mints, queries := 0, 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch r.URL.Path {
		case "/api/v1/daemons/" + workspace + "/access-tickets":
			mints++
			var body map[string]string
			if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["action"] != "files.read" || body["operation_uuid"] != operation {
				t.Error("invalid ticket metadata")
			}
			io.WriteString(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"POST","gateway_path":"/v1/workspaces/`+workspace+`/files/query"}}`)
		case "/v1/workspaces/" + workspace + "/files/query":
			queries++
			body, _ := io.ReadAll(r.Body)
			if r.Method != "POST" || string(body) != `{"operation":"upload_receipt"}` || r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
				t.Error("invalid guest receipt query")
			}
			io.WriteString(w, `{"status":"outcome_unknown"}`)
		default:
			t.Error("unexpected endpoint")
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, _ := New(server.URL, "test-token")
	for i := 0; i < 2; i++ {
		receipt, err := c.GetUploadReceipt(context.Background(), workspace, operation)
		if err != nil || receipt.Status != "outcome_unknown" {
			t.Fatalf("receipt: %+v %v", receipt, err)
		}
	}
	if mints != 2 || queries != 2 {
		t.Fatal("receipt lookup reused authority or replayed upload")
	}
}
