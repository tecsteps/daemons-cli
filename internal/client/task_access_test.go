package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

const accessTaskID = "aaf324d3-dcc9-469a-986e-19e0d6779422"

func taskQueryServer(t *testing.T, reply func(http.ResponseWriter, map[string]any)) (*Client, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch r.URL.Path {
		case "/api/v1":
			io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case "/api/v1/daemons/workspace/access-tickets":
			var metadata map[string]string
			if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
				t.Error("invalid metadata request")
			}
			if len(metadata) != 2 || metadata["action"] != "tasks.read" || !payloadUUID.MatchString(metadata["operation_uuid"]) || r.URL.RawQuery != "" {
				t.Error("task content entered the metadata request")
			}
			if r.Header.Get("Authorization") != "Bearer synthetic-cp-token" {
				t.Error("missing control-plane authentication")
			}
			io.WriteString(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"POST","gateway_path":"/v1/workspaces/workspace/tasks/query"}}`)
		case "/v1/workspaces/workspace/tasks/query":
			calls.Add(1)
			if r.Method != "POST" || r.URL.RawQuery != "" || r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
				t.Error("wrong task relay boundary")
			}
			var selector map[string]any
			if err := json.NewDecoder(r.Body).Decode(&selector); err != nil {
				t.Error("invalid guest selector")
			}
			reply(w, selector)
		default:
			t.Error("legacy task endpoint or unexpected redirect was reached")
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	c, err := New(server.URL, "synthetic-cp-token")
	if err != nil {
		t.Fatal(err)
	}
	return c, &calls
}

func TestV2TaskQueriesUseOnlyTheGuestContentChannel(t *testing.T) {
	c, calls := taskQueryServer(t, func(w http.ResponseWriter, selector map[string]any) {
		if len(selector) != 2 {
			t.Error("unexpected query fields")
		}
		row := map[string]any{"id": accessTaskID, "status": "succeeded", "result": map[string]any{"final_text": "private guest task result"}}
		if selector["operation"] == "list" {
			if selector["limit"] != float64(20) {
				t.Error("limit changed")
			}
			json.NewEncoder(w).Encode(map[string]any{"data": []any{row}, "meta": map[string]any{}})
		} else {
			if selector["operation"] != "show" || selector["task_id"] != accessTaskID {
				t.Error("wrong guest task selector")
			}
			json.NewEncoder(w).Encode(map[string]any{"data": row, "meta": map[string]any{}})
		}
	})
	list, err := c.ListTasks(context.Background(), "workspace", 20)
	if err != nil || len(list.Data) != 1 {
		t.Fatalf("list: %v", err)
	}
	shown, err := c.ShowTask(context.Background(), "workspace", accessTaskID)
	if err != nil || shown.Data.Result["final_text"] != "private guest task result" || !strings.Contains(string(shown.Raw), "private guest task result") {
		t.Fatalf("show: %v", err)
	}
	if calls.Load() != 2 {
		t.Fatal("missing guest requests")
	}
}

func TestV2TaskQueryFailuresNeverFallBackOrRetry(t *testing.T) {
	for _, mode := range []string{"revoked", "redirect", "unavailable", "oversize", "trailing", "wrong-task", "missing-status"} {
		t.Run(mode, func(t *testing.T) {
			c, calls := taskQueryServer(t, func(w http.ResponseWriter, _ map[string]any) {
				switch mode {
				case "revoked":
					w.WriteHeader(403)
				case "redirect":
					w.Header().Set("Location", "/api/v1/daemons/workspace/tasks")
					w.WriteHeader(307)
				case "unavailable":
					w.WriteHeader(503)
				case "oversize":
					io.WriteString(w, strings.Repeat(" ", 128*1024+1))
				case "trailing":
					io.WriteString(w, `{"data":{"id":"`+accessTaskID+`","status":"succeeded"}} {}`)
				case "wrong-task":
					io.WriteString(w, `{"data":{"id":"different-task","status":"succeeded"}}`)
				case "missing-status":
					io.WriteString(w, `{"data":{"id":"`+accessTaskID+`"}}`)
				}
			})
			if _, err := c.ShowTask(context.Background(), "workspace", accessTaskID); err == nil {
				t.Fatal("invalid response accepted")
			}
			if calls.Load() != 1 {
				t.Fatal("query was replayed")
			}
		})
	}
}
