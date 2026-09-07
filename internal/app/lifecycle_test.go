package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestE7RenameAndDeletePreconditions(t *testing.T) {
	for _, action := range []string{"rename", "delete", "destroy"} {
		t.Run(action, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("If-Match") != `"pinned"` {
					t.Errorf("missing precondition: %v", r.Header)
				}
				if action == "rename" {
					if r.Method != "PATCH" {
						t.Errorf("method %s", r.Method)
					}
					io.WriteString(w, lifecycleShow)
					return
				}
				if r.Method != "DELETE" {
					t.Errorf("method %s", r.Method)
				}
				problem(w, 409, "confirmation_required", "Browser confirmation required.", `{"approve_url":"https://daemons.run/settings","confirmation_id":"approval"}`)
			})
			var out, stderr bytes.Buffer
			args := []string{"--host", server.URL, "--json", action, lifecycleWorkspace}
			if action == "rename" {
				args = append(args, "new-name")
			}
			args = append(args, "--etag", `"pinned"`, "--idempotency-key", "pinned-key-1")
			want := 6
			if action == "rename" {
				want = 0
			}
			if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != want {
				t.Fatalf("exit %d: %s", code, out.String())
			}
			if len(record.requests) != 2 {
				t.Fatalf("requests %v", record.requests)
			}
			if action == "rename" && record.bodies[1]["name"] != "new-name" {
				t.Fatalf("body %v", record.bodies[1])
			}
			if action != "rename" && (!strings.Contains(stderr.String(), "pinned-key-1") || !strings.Contains(stderr.String(), `"pinned"`)) {
				t.Fatalf("replay lost approval identity: %s", stderr.String())
			}
		})
	}
}

func TestE7CtrlCStopsOnlyLocalPolling(t *testing.T) {
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":{"id":"op","type":"daemon.resume","state":"waiting","phase":"placement"},"meta":[]}`)
	})
	var out, stderr bytes.Buffer
	deps := phaseOneDependencies(t, server.Client(), &out, &stderr)
	deps.Sleep = func(context.Context, time.Duration) error { return context.Canceled }
	if code := Run(context.Background(), []string{"--host", server.URL, "operations", "wait", "op"}, deps); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if len(record.requests) != 1 || !strings.HasPrefix(record.requests[0], "GET ") || !strings.Contains(stderr.String(), "wait_interrupted") {
		t.Fatalf("requests %v stderr %s", record.requests, stderr.String())
	}
}

func TestE7ReplayRetainsForceOfferAndRevision(t *testing.T) {
	for _, action := range []string{"restart", "resize"} {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
			if r.Method == "GET" {
				w.Header().Set("ETag", `"first-revision"`)
				io.WriteString(w, lifecycleShow)
				return
			}
			connection, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			connection.Close()
		})
		var out, stderr bytes.Buffer
		deps := phaseOneDependencies(t, server.Client(), &out, &stderr)
		deps.NewIdempotencyKey = func() (string, error) { return "", errors.New("must not generate") }
		args := []string{"--host", server.URL, action, lifecycleWorkspace, "--idempotency-key", "original-key-1"}
		if action == "restart" {
			args = append(args, "--force")
		} else {
			args = append(args, "--size", "large", "--accepted-offer", lifecycleOther)
		}
		if code := Run(context.Background(), args, deps); code != 8 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		for _, part := range []string{"original-key-1", `"first-revision"`, action} {
			if !strings.Contains(stderr.String(), part) {
				t.Fatalf("missing %s: %s", part, stderr.String())
			}
		}
		if action == "restart" && !strings.Contains(stderr.String(), "--force") {
			t.Fatal("force lost")
		}
		if action == "resize" && !strings.Contains(stderr.String(), lifecycleOther) {
			t.Fatal("consent lost")
		}
	}
}

const lifecycleWorkspace = "11111111-1111-4111-8111-111111111111"
const lifecycleOther = "22222222-2222-4222-8222-222222222222"
const lifecycleAck = `{"data":{"uuid":"33333333-3333-4333-8333-333333333333","status":"queued"},"meta":[]}`
const lifecycleShow = `{"data":{"id":"11111111-1111-4111-8111-111111111111","name":"research","status":"running","primary_agent":"codex","disk":{"referenced_bytes":null,"allocation_bytes":null,"headroom_bytes":null,"sampled_at":null}},"meta":[]}`

func TestE7LifecycleCommandMatrix(t *testing.T) {
	for _, action := range []string{"start", "stop", "restart", "pause", "resume", "resize", "force-restart"} {
		t.Run(action, func(t *testing.T) {
			wireAction := action
			if action == "force-restart" {
				wireAction = "restart"
			}
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
				if r.Method == "GET" {
					w.Header().Set("ETag", `"revision-1"`)
					io.WriteString(w, lifecycleShow)
					return
				}
				if r.Method != "POST" || r.URL.Path != "/api/v1/daemons/"+lifecycleWorkspace+"/"+wireAction {
					t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
				}
				if r.Header.Get("If-Match") != `"revision-1"` || r.Header.Get("Idempotency-Key") != "lifecycle-key-1" {
					t.Errorf("headers: %v", r.Header)
				}
				w.WriteHeader(202)
				io.WriteString(w, lifecycleAck)
			})
			var out, stderr bytes.Buffer
			args := []string{"--host", server.URL, "--json", action, lifecycleWorkspace, "--idempotency-key", "lifecycle-key-1"}
			if action == "resize" {
				args = append(args, "--size", "large", "--accepted-offer", lifecycleOther)
			}
			if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != 0 {
				t.Fatalf("exit %d: %s %s", code, out.String(), stderr.String())
			}
			if out.String() != lifecycleAck+"\n" {
				t.Fatalf("wire document changed: %s", out.String())
			}
			body := record.bodies[len(record.bodies)-1]
			if wireAction == "restart" && body["force"] != (action == "force-restart") {
				t.Fatalf("force: %v", body)
			}
			if action == "resize" && (body["size"] != "large" || body["accepted_offer_id"] != lifecycleOther) {
				t.Fatalf("resize: %v", body)
			}
		})
	}
}

func TestE7CreateMetadataAndCompactOperation(t *testing.T) {
	response := `{"data":{"id":"` + lifecycleWorkspace + `","name":"research","status":"creating","primary_agent":"codex"},"meta":{"operation":{"uuid":"operation-id"}}}`
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
		if r.Method != "POST" || r.URL.Path != "/api/v1/daemons" {
			t.Errorf("request %s %s", r.Method, r.URL.Path)
		}
		w.WriteHeader(202)
		io.WriteString(w, response)
	})
	for _, alias := range []string{"create", "spawn"} {
		var out, stderr bytes.Buffer
		args := []string{"--host", server.URL, "--json", alias, "research", "--size", "small", "--variant", "burstable", "--agent", "codex", "--assigned-user", lifecycleWorkspace, "--creation-team", lifecycleOther, "--team", lifecycleOther, "--accepted-offer", lifecycleOther, "--idempotency-key", "create-key-1"}
		if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != 0 {
			t.Fatalf("exit %d: %s", code, out.String())
		}
		if out.String() != response+"\n" {
			t.Fatalf("wire document: %s", out.String())
		}
		body := record.bodies[len(record.bodies)-1]
		if len(body) != 9 || body["source"] != "empty" || body["assigned_user_id"] != lifecycleWorkspace || body["accepted_offer_id"] != lifecycleOther {
			t.Fatalf("metadata: %v", body)
		}
	}
}

func TestE7DenialsPreserveWireAndExitCodes(t *testing.T) {
	for _, tc := range []struct {
		status, exit int
		code         string
	}{{401, 3, "authentication_required"}, {404, 4, "not_found"}, {403, 5, "capability_denied"}, {409, 6, "confirmation_required"}, {429, 7, "rate_limited"}, {504, 8, "outcome_unknown"}, {412, 1, "precondition_failed"}, {428, 1, "precondition_required"}} {
		t.Run(tc.code, func(t *testing.T) {
			raw, _ := json.Marshal(map[string]any{"type": "https://daemons.run/problems/" + tc.code, "title": "Problem", "status": tc.status, "code": tc.code, "detail": "Denied.", "request_id": "req-1", "errors": []any{}, "meta": []any{}})
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				w.Write(raw)
			})
			var out, stderr bytes.Buffer
			args := []string{"--host", server.URL, "--json", "stop", lifecycleWorkspace, "--etag", `"original"`, "--idempotency-key", "denial-key-1"}
			if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != tc.exit {
				t.Fatalf("exit %d: %s", code, out.String())
			}
			if out.String() != string(raw)+"\n" || len(record.requests) != 2 {
				t.Fatalf("changed denial or replayed: %s %v", out.String(), record.requests)
			}
		})
	}
}

func TestE7OperationWaitCancelRetry(t *testing.T) {
	for _, action := range []string{"wait", "cancel", "retry"} {
		t.Run(action, func(t *testing.T) {
			state := "succeeded"
			if action == "cancel" {
				state = "cancelling"
			}
			raw := `{"data":{"id":"op","type":"daemon.resume","state":"` + state + `","phase":"cleanup","daemon_id":"` + lifecycleWorkspace + `","reason_code":null,"retryable":false,"receipts":[]},"meta":[]}`
			server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
				path := "/api/v1/operations/op"
				method := "GET"
				if action != "wait" {
					path += "/" + action
					method = "POST"
				}
				if r.URL.Path != path || r.Method != method {
					t.Errorf("request %s %s", r.Method, r.URL.Path)
				}
				io.WriteString(w, raw)
			})
			var out, stderr bytes.Buffer
			args := []string{"--host", server.URL, "--json", "operations", action, "op"}
			if action != "wait" {
				args = append(args, "--idempotency-key", "operation-key-1")
			}
			if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != 0 {
				t.Fatalf("exit %d: %s", code, out.String())
			}
			if out.String() != raw+"\n" {
				t.Fatalf("wire response %s", out.String())
			}
		})
	}
}

func TestE7BulkPartialPreservesEveryOutcome(t *testing.T) {
	raw := `{"data":{"outcomes":[{"daemon_id":"` + lifecycleWorkspace + `","operation_id":"op","status":"accepted","code":null},{"daemon_id":"` + lifecycleOther + `","operation_id":null,"status":"failed","code":"operation_failed"}]},"meta":[]}`
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/daemons/bulk/stop" {
			t.Errorf("path %s", r.URL.Path)
		}
		io.WriteString(w, raw)
	})
	var out, stderr bytes.Buffer
	args := []string{"--host", server.URL, "--json", "stop", lifecycleWorkspace, lifecycleOther, lifecycleWorkspace, "--idempotency-key", "bulk-key-1"}
	if code := Run(context.Background(), args, phaseOneDependencies(t, server.Client(), &out, &stderr)); code != 1 {
		t.Fatalf("exit %d", code)
	}
	if out.String() != raw+"\n" || len(record.bodies[len(record.bodies)-1]["daemon_ids"].([]any)) != 2 {
		t.Fatalf("outcomes %s", out.String())
	}
}

func TestE7LocalTimeoutDoesNotCancel(t *testing.T) {
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, `{"data":{"id":"op","type":"daemon.resume","state":"waiting","phase":"placement"},"meta":[]}`)
	})
	var out, stderr bytes.Buffer
	deps := phaseOneDependencies(t, server.Client(), &out, &stderr)
	now := time.Unix(0, 0)
	deps.Now = func() time.Time { return now }
	deps.Sleep = func(_ context.Context, d time.Duration) error { now = now.Add(d); return nil }
	args := []string{"--host", server.URL, "operations", "wait", "op", "--wait-timeout", "1s"}
	if code := Run(context.Background(), args, deps); code != 8 {
		t.Fatalf("exit %d: %s", code, stderr.String())
	}
	for _, request := range record.requests {
		if !strings.HasPrefix(request, "GET ") {
			t.Fatalf("remote mutation: %s", request)
		}
	}
}

func TestE7UnavailablePayloadAndBulkDeleteMakeNoRequest(t *testing.T) {
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, w http.ResponseWriter, r *http.Request) { t.Errorf("unexpected request") })
	for _, args := range [][]string{{"operations", "continue", "op", "--payload-file", "/does-not-exist"}, {"delete", lifecycleWorkspace, lifecycleOther}, {"create", "research", "--size", "small", "--variant", "burstable", "--agent", "codex", "--assigned-user", lifecycleWorkspace, "--creation-team", lifecycleOther, "--repo", "https://example.test/private"}} {
		var out, stderr bytes.Buffer
		if code := Run(context.Background(), append([]string{"--host", server.URL}, args...), phaseOneDependencies(t, server.Client(), &out, &stderr)); code == 0 {
			t.Fatal("unexpected success")
		}
	}
	if len(record.requests) != 0 {
		t.Fatalf("requests %v", record.requests)
	}
}
