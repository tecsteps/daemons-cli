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

func TestV2TaskSubmissionKeepsPayloadInGuestChannel(t *testing.T) {
	const workspace = "baf324d3-dcc9-469a-986e-19e0d6779422"
	const organization = "caf324d3-dcc9-469a-986e-19e0d6779422"
	const folder = "daf324d3-dcc9-469a-986e-19e0d6779422"
	for _, outcome := range []string{"queued", "completed", "denied", "wrong-task", "trailing", "oversized"} {
		t.Run(outcome, func(t *testing.T) {
			var taskID, operationID string
			submissions := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Daemons-Api-Version", "v1")
				switch {
				case r.URL.Path == "/api/v1":
					io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
				case strings.HasSuffix(r.URL.Path, "/access-tickets"):
					var metadata map[string]string
					json.NewDecoder(r.Body).Decode(&metadata)
					suffix, method := "/tasks/query", "POST"
					if metadata["action"] == "tasks.submit" {
						if len(metadata) != 3 {
							t.Error("content in submit metadata")
						}
						taskID, operationID = metadata["task_uuid"], metadata["operation_uuid"]
						if !payloadUUID.MatchString(taskID) || !payloadUUID.MatchString(operationID) {
							t.Error("invalid task identifiers")
						}
						suffix, method = "/tasks/"+taskID, "PUT"
					} else if metadata["action"] != "tasks.read" || len(metadata) != 2 {
						t.Error("invalid configuration metadata")
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ticket": "guest.ticket", "ticket_version": 2,
						"expires_in": 30, "method": method, "gateway_path": "/v1/workspaces/" + workspace + suffix,
						"target": LocalPayloadTarget{OrganizationID: organization, WorkspaceID: workspace, RuntimeGeneration: 1, AssignmentGeneration: 1}}})
				case r.URL.Path == "/v1/workspaces/"+workspace+"/tasks/query":
					body, _ := io.ReadAll(r.Body)
					if string(body) != `{"operation":"configuration"}` {
						t.Error("wrong configuration query")
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"folders": []any{map[string]string{"id": folder, "relative_path": "default"}},
						"default_agent": "codex", "permission_mode": "approval", "timeout_seconds": 1800}})
				case r.URL.Path == "/v1/workspaces/"+workspace+"/tasks/"+taskID && taskID != "":
					submissions++
					if r.Method != "PUT" || r.Header.Get("Authorization") != "DaemonsTicket guest.ticket" || r.Header.Get("Content-Type") != "application/vnd.daemons.local-payload+json" {
						t.Error("wrong task payload transport")
					}
					var payload map[string]any
					json.NewDecoder(r.Body).Decode(&payload)
					document, ok := payload["document"].(map[string]any)
					if !ok || document["prompt"] != "private task prompt" || document["folder_id"] != folder || document["task_id"] != taskID || document["permission_mode"] != "approval" || payload["operation_id"] != operationID {
						t.Error("incorrect task envelope")
					}
					if outcome == "denied" {
						w.WriteHeader(503)
						return
					}
					if outcome == "oversized" {
						io.WriteString(w, strings.Repeat("x", 128*1024+1))
						return
					}
					id := taskID
					status := "queued"
					if outcome == "completed" {
						status = "completed"
					}
					if outcome == "wrong-task" {
						id = folder
					}
					json.NewEncoder(w).Encode(map[string]any{"receipt": LocalPayloadReceipt{LocalPayloadTarget: LocalPayloadTarget{OrganizationID: organization, WorkspaceID: workspace, RuntimeGeneration: 1, AssignmentGeneration: 1},
						PayloadID: operationID, OperationID: operationID, Revision: 1, Phase: "applied"}, "task": map[string]string{"id": id, "attempt_id": folder, "status": status}})
					if outcome == "trailing" {
						io.WriteString(w, `{}`)
					}
				default:
					t.Error("legacy endpoint or unexpected destination reached")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			c, err := New(server.URL, "cp-token")
			if err != nil {
				t.Fatal(err)
			}
			result, err := c.CreateTask(context.Background(), workspace, TaskRequest{Prompt: "private task prompt", PermissionMode: "approval-auto-deny"}, "local-key")
			if (err == nil) != (outcome == "queued" || outcome == "completed") {
				t.Fatalf("unexpected submission outcome: %v", err)
			}
			if outcome == "queued" && (result.Data.ID != taskID || result.Data.Status != "queued" || len(result.Raw) == 0) {
				t.Error("missing queued task receipt")
			}
			if submissions != 1 {
				t.Errorf("submission replayed: %d", submissions)
			}
			if err == nil {
				firstTask, firstOperation := taskID, operationID
				repeated, retryErr := c.CreateTask(context.Background(), workspace, TaskRequest{Prompt: "private task prompt", PermissionMode: "approval-auto-deny"}, "local-key")
				if retryErr != nil || repeated.Data.ID != firstTask || operationID != firstOperation || repeated.Data.Status != outcome || submissions != 2 {
					t.Fatalf("explicit retry did not preserve identity: %v", retryErr)
				}
			}
		})
	}
}

func TestTaskSubmissionIdentityIsScopedAndStable(t *testing.T) {
	first := taskSubmissionID("workspace-a", "key-a", "task")
	if !payloadUUID.MatchString(first) || first != taskSubmissionID("workspace-a", "key-a", "task") {
		t.Fatal("invalid or unstable task identity")
	}
	for _, other := range []string{taskSubmissionID("workspace-b", "key-a", "task"), taskSubmissionID("workspace-a", "key-b", "task"), taskSubmissionID("workspace-a", "key-a", "operation")} {
		if first == other {
			t.Fatal("task identity scope collision")
		}
	}
}
