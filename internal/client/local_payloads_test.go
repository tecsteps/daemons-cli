package client

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const payloadDaemonID = "11111111-1111-4111-8111-111111111111"
const payloadOperationID = "22222222-2222-4222-8222-222222222222"

func payloadTestTarget() LocalPayloadTarget {
	return LocalPayloadTarget{OrganizationID: "33333333-3333-4333-8333-333333333333", WorkspaceID: payloadDaemonID, RuntimeGeneration: 2, AssignmentGeneration: 3}
}

func payloadTestReceipt() LocalPayloadReceipt {
	return LocalPayloadReceipt{LocalPayloadTarget: payloadTestTarget(), PayloadID: payloadOperationID, OperationID: payloadOperationID, Revision: 1, Phase: "applied"}
}

func TestLocalPayloadStreamsOnceAndRecoversDroppedAcknowledgmentWithFreshReceipt(t *testing.T) {
	for _, dropped := range []bool{false, true} {
		t.Run(fmt.Sprint(dropped), func(t *testing.T) {
			var minted, uploads, receipts atomic.Int32
			payload := strings.Repeat("synthetic-private-content-", 8192)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Daemons-Api-Version", "v1")
				if r.URL.Path == "/api/v1" {
					io.WriteString(w, `{"data":{"version":"v1"}}`)
					return
				}
				if r.URL.Path == "/api/v1/daemons/"+payloadDaemonID+"/access-tickets" {
					var body map[string]string
					if json.NewDecoder(r.Body).Decode(&body) != nil || len(body) != 2 || body["operation_uuid"] != payloadOperationID || r.URL.RawQuery != "" {
						t.Error("content entered metadata request")
					}
					method := "PUT"
					if body["action"] == "local_payload.receipt" {
						method = "GET"
					} else if body["action"] != "local_payload.put" {
						t.Error("wrong action")
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ticket": fmt.Sprintf("opaque.%d", minted.Add(1)), "ticket_version": 2,
						"expires_in": 30, "method": method, "gateway_path": "/v1/workspaces/" + payloadDaemonID + "/local-payloads/" + payloadOperationID, "target": payloadTestTarget()}})
					return
				}
				if r.URL.Path != "/v1/workspaces/"+payloadDaemonID+"/local-payloads/"+payloadOperationID || r.URL.RawQuery != "" ||
					r.Header.Get("Authorization") != fmt.Sprintf("DaemonsTicket opaque.%d", minted.Load()) || r.Header.Get("Content-Type") != "application/vnd.daemons.local-payload+json" {
					t.Error("relay identity or MIME boundary")
					w.WriteHeader(400)
					return
				}
				if r.Method == "PUT" {
					uploads.Add(1)
					var body strings.Builder
					if _, err := io.Copy(&body, r.Body); err != nil || body.String() != payload {
						t.Error("payload changed")
					}
					if dropped {
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						connection.Close()
						return
					}
				} else if r.Method == "GET" {
					receipts.Add(1)
					var body strings.Builder
					io.Copy(&body, r.Body)
					if body.Len() != 0 {
						t.Error("receipt lookup sent content")
					}
				} else {
					t.Error("wrong method")
				}
				json.NewEncoder(w).Encode(payloadTestReceipt())
			}))
			defer server.Close()
			c, _ := New(server.URL, "CP-SECRET")
			result, err := c.PutLocalPayload(context.Background(), payloadDaemonID, payloadOperationID, strings.NewReader(payload))
			if dropped {
				if err == nil || errs.Code(err) != "relay_outcome_unknown" {
					t.Fatalf("ambiguous upload: %v", err)
				}
			} else if err != nil || result != payloadTestReceipt() {
				t.Fatalf("upload receipt: %v", err)
			}
			result, err = c.GetLocalPayloadReceipt(context.Background(), payloadDaemonID, payloadOperationID)
			if err != nil || result != payloadTestReceipt() {
				t.Fatalf("fresh receipt: %v", err)
			}
			if minted.Load() != 2 || uploads.Load() != 1 || receipts.Load() != 1 {
				t.Fatal("missing receipt or replayed upload")
			}
		})
	}
}

func TestLocalPayloadReceiptsRejectUnboundMalformedOrContentBearingData(t *testing.T) {
	valid, _ := json.Marshal(payloadTestReceipt())
	if _, err := decodeLocalPayloadReceipt(valid, payloadTestTarget(), payloadOperationID); err != nil {
		t.Fatal(err)
	}
	for _, raw := range []string{
		strings.Replace(string(valid), `"revision":1`, `"revision":null`, 1),
		strings.Replace(string(valid), `"revision":1`, `"revision":9007199254740992`, 1),
		strings.Replace(string(valid), `"phase":"applied"`, `"phase":"applied","phase":"rejected"`, 1),
		strings.Replace(string(valid), `"error_code":null`, `"error_code":"PRIVATE"`, 1),
		strings.Replace(string(valid), `"assignment_generation":3`, `"assignment_generation":4`, 1),
		strings.Replace(string(valid), `"payload_id":"`+payloadOperationID+`"`, `"payload_id":"44444444-4444-4444-8444-444444444444"`, 1),
		strings.TrimSuffix(string(valid), "}") + `,"prompt":"PRIVATE"}`,
		string(valid) + `{}`,
		`{}`,
	} {
		if _, err := decodeLocalPayloadReceipt([]byte(raw), payloadTestTarget(), payloadOperationID); err == nil || strings.Contains(err.Error(), "PRIVATE") {
			t.Fatalf("invalid receipt accepted or disclosed: %v", err)
		}
	}
}

func TestLocalPayloadInvalidIdentifiersDoNotOpenControlPlane(t *testing.T) {
	c, _ := New("http://127.0.0.1:1", "synthetic")
	if _, err := c.PutLocalPayload(context.Background(), "private-path", payloadOperationID, strings.NewReader("private")); errs.Code(err) != "usage_error" {
		t.Fatal(err)
	}
	if _, err := c.PutLocalPayload(context.Background(), payloadDaemonID, payloadOperationID, nil); errs.Code(err) != "invalid_payload" {
		t.Fatal(err)
	}
}
