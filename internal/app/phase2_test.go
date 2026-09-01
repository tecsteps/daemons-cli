package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

const (
	spawnResponse   = `{"data":{"id":"daemon-uuid","name":"research","status":"provisioning","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"},"future_daemon_field":"kept"},"meta":{"operation":{"id":"operation-uuid","type":"daemon.spawn","status":"queued","resource":{"type":"daemon","id":"daemon-uuid"},"result":{},"retryable":false},"future_meta":"kept"},"future_envelope":"kept"}`
	destroyResponse = `{"data":{"id":"operation-uuid","type":"daemon.destroy","status":"succeeded","resource":{"type":"daemon","id":"daemon-uuid"},"result":{"daemon_status":"destroying"},"retryable":false},"meta":[],"future_envelope":"kept"}`
	daemonResponse  = `{"data":{"id":"daemon-uuid","name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"}},"meta":[]}`
	problemPrefix   = `{"type":"https://daemons.run/problems/`
)

type phaseTwoServer struct {
	requests []string
	headers  []http.Header
	bodies   []map[string]any
}

func newPhaseTwoServer(t *testing.T, handler func(record *phaseTwoServer, writer http.ResponseWriter, request *http.Request)) (*httptest.Server, *phaseTwoServer) {
	t.Helper()
	record := &phaseTwoServer{}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		record.requests = append(record.requests, request.Method+" "+request.URL.RequestURI())
		record.headers = append(record.headers, request.Header.Clone())
		var body map[string]any
		_ = json.NewDecoder(request.Body).Decode(&body)
		record.bodies = append(record.bodies, body)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		if request.URL.Path == "/api/v1" {
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
			return
		}
		handler(record, writer, request)
	}))
	t.Cleanup(server.Close)
	return server, record
}

func problem(writer http.ResponseWriter, status int, code, detail, meta string) {
	writer.Header().Set("Content-Type", "application/problem+json")
	writer.WriteHeader(status)
	io.WriteString(writer, problemPrefix+code+`","title":"Problem","status":`+itoa(status)+`,"code":"`+code+`","detail":"`+detail+`","request_id":"req-1","errors":{},"meta":`+meta+`}`)
}

func itoa(value int) string {
	return strings.TrimSpace(strings.ReplaceAll(string(rune('0'+value/100))+string(rune('0'+value/10%10))+string(rune('0'+value%10)), " ", ""))
}

func TestPhaseTwoCommandsPreserveCanonicalJSON(t *testing.T) {
	operationList := `{"data":[{"id":"operation-uuid","type":"daemon.start","status":"succeeded","resource":{"type":"daemon","id":"daemon-uuid"},"result":{},"retryable":false,"future":"kept"}],"meta":{"next_cursor":null},"future_envelope":"kept"}`
	retryResponse := `{"data":{"id":"operation-uuid","type":"daemon.retry","status":"succeeded","resource":{"type":"daemon","id":"daemon-uuid"},"result":{},"retryable":false},"meta":[],"future_envelope":"kept"}`
	tests := []struct {
		name      string
		arguments []string
		responses map[string]string
		want      []string
		key       string
		body      map[string]any
		ifMatch   string
	}{
		{
			name:      "operations list",
			arguments: []string{"operations", "list", "--limit", "5"},
			responses: map[string]string{"GET /api/v1/operations?limit=5": operationList},
			want:      []string{"GET /api/v1/operations?limit=5"},
		},
		{
			name:      "daemons spawn by server uuid",
			arguments: []string{"daemons", "spawn", "research", "--server", "11111111-2222-3333-4444-555555555555", "--agent", "codex", "--disk-quota-gb", "20", "--idempotency-key", "phase2-spawn-key"},
			responses: map[string]string{"POST /api/v1/daemons": spawnResponse},
			want:      []string{"GET /api/v1", "POST /api/v1/daemons"},
			key:       "phase2-spawn-key",
			body:      map[string]any{"server_id": "11111111-2222-3333-4444-555555555555", "name": "research", "primary_agent": "codex", "disk_quota_gb": float64(20)},
		},
		{
			name:      "spawn alias resolves server by exact name",
			arguments: []string{"spawn", "research", "--server", "host", "--idempotency-key", "phase2-spawn-key"},
			responses: map[string]string{
				"GET /api/v1/servers":  `{"data":[{"id":"server-uuid","name":"host","status":"running"}],"meta":{}}`,
				"POST /api/v1/daemons": spawnResponse,
			},
			want: []string{"GET /api/v1/servers", "GET /api/v1", "POST /api/v1/daemons"},
			key:  "phase2-spawn-key",
			body: map[string]any{"server_id": "server-uuid", "name": "research"},
		},
		{
			name:      "daemons retry",
			arguments: []string{"daemons", "retry", "daemon-uuid", "--idempotency-key", "phase2-retry-key"},
			responses: map[string]string{"POST /api/v1/daemons/daemon-uuid/retry": retryResponse},
			want:      []string{"GET /api/v1", "POST /api/v1/daemons/daemon-uuid/retry"},
			key:       "phase2-retry-key",
		},
		{
			name:      "daemons destroy fetches the etag then sends If-Match",
			arguments: []string{"daemons", "destroy", "daemon-uuid", "--idempotency-key", "phase2-destroy-key"},
			responses: map[string]string{
				"GET /api/v1/daemons/daemon-uuid":    daemonResponse,
				"DELETE /api/v1/daemons/daemon-uuid": destroyResponse,
			},
			want:    []string{"GET /api/v1/daemons/daemon-uuid", "GET /api/v1", "DELETE /api/v1/daemons/daemon-uuid"},
			key:     "phase2-destroy-key",
			ifMatch: `"etag-1"`,
		},
		{
			name:      "destroy alias with a pinned etag skips the fetch",
			arguments: []string{"destroy", "daemon-uuid", "--etag", `"pinned"`, "--idempotency-key", "phase2-destroy-key"},
			responses: map[string]string{"DELETE /api/v1/daemons/daemon-uuid": destroyResponse},
			want:      []string{"GET /api/v1", "DELETE /api/v1/daemons/daemon-uuid"},
			key:       "phase2-destroy-key",
			ifMatch:   `"pinned"`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
				response, ok := test.responses[request.Method+" "+request.URL.RequestURI()]
				if !ok {
					t.Errorf("unexpected request %s %s", request.Method, request.URL.RequestURI())
					http.NotFound(writer, request)
					return
				}
				if request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/daemons/") {
					writer.Header().Set("ETag", `"etag-1"`)
				}
				if request.Method != http.MethodGet {
					writer.WriteHeader(http.StatusAccepted)
				}
				io.WriteString(writer, response)
			})

			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			arguments := append([]string{"--json", "--host", server.URL}, test.arguments...)
			if code := Run(context.Background(), arguments, dependencies); code != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
			}
			final := test.responses[test.want[len(test.want)-1]]
			if output.String() != final+"\n" || errorOutput.Len() != 0 {
				t.Fatalf("stdout = %q, stderr = %q, want %q", output.String(), errorOutput.String(), final)
			}
			if !slices.Equal(record.requests, test.want) {
				t.Fatalf("requests = %#v, want %#v", record.requests, test.want)
			}
			last := len(record.requests) - 1
			if record.headers[last].Get("Idempotency-Key") != test.key || record.headers[last].Get("If-Match") != test.ifMatch {
				t.Fatalf("headers = %v", record.headers[last])
			}
			if test.body != nil {
				got, _ := json.Marshal(record.bodies[last])
				want, _ := json.Marshal(test.body)
				if string(got) != string(want) {
					t.Fatalf("body = %s, want %s", got, want)
				}
			}
		})
	}
}

func TestPhaseTwoLocalValidationSendsNothing(t *testing.T) {
	tests := map[string][]string{
		"spawn without server":           {"spawn", "research", "--idempotency-key", "phase2-spawn-key"},
		"spawn without name":             {"spawn", "--server", "host", "--idempotency-key", "phase2-spawn-key"},
		"spawn bad quota":                {"spawn", "research", "--server", "host", "--disk-quota-gb", "zero", "--idempotency-key", "phase2-spawn-key"},
		"spawn unknown flag":             {"spawn", "research", "--server", "host", "--colour", "red", "--idempotency-key", "phase2-spawn-key"},
		"spawn non-interactive no key":   {"spawn", "research", "--server", "host"},
		"destroy non-interactive no key": {"destroy", "daemon-uuid"},
		"retry bad wait timeout":         {"retry", "daemon-uuid", "--wait", "--wait-timeout", "soon", "--idempotency-key", "phase2-retry-key"},
		"operations list bad limit":      {"operations", "list", "--limit", "0"},
		"operations list extra argument": {"operations", "list", "extra"},
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "must not be called", http.StatusInternalServerError)
			})
			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			code := Run(context.Background(), append([]string{"--host", server.URL}, arguments...), dependencies)
			if code != 2 || len(record.requests) != 0 {
				t.Fatalf("exit = %d, requests = %v, stderr = %q", code, record.requests, errorOutput.String())
			}
		})
	}
}

func TestSpawnValidationFailureRendersFieldErrors(t *testing.T) {
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(writer, `{"status":422,"code":"validation_failed","detail":"One or more fields are invalid.","errors":{"name":["The name has already been taken."]},"meta":{}}`)
	})
	arguments := []string{"--host", server.URL, "spawn", "research", "--server", "11111111-2222-3333-4444-555555555555", "--idempotency-key", "phase2-spawn-key"}

	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	if code := Run(context.Background(), arguments, dependencies); code != 1 {
		t.Fatalf("exit = %d", code)
	}
	if !strings.Contains(errorOutput.String(), "validation_failed") || !strings.Contains(errorOutput.String(), "name: The name has already been taken.") {
		t.Fatalf("stderr = %q", errorOutput.String())
	}

	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), append([]string{"--json"}, arguments...), dependencies); code != 1 {
		t.Fatalf("json exit = %d", code)
	}
	if !strings.Contains(output.String(), `"code":"validation_failed"`) || !strings.Contains(output.String(), `"errors":{"name":`) {
		t.Fatalf("json stdout = %q", output.String())
	}
}

func TestDestroyConfirmationRequired(t *testing.T) {
	newServer := func(t *testing.T) (*httptest.Server, *phaseTwoServer) {
		return newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.Method == http.MethodGet {
				writer.Header().Set("ETag", `"etag-1"`)
				io.WriteString(writer, daemonResponse)
				return
			}
			problem(writer, 409, "confirmation_required", "Destroying this daemon requires browser confirmation.", `{"confirmation_id":"confirmation-uuid","approve_url":"https://daemons.run/settings?tab=control-plane","expires_at":"2026-09-01T12:00:00+00:00"}`)
		})
	}

	t.Run("json writes the canonical problem and never opens a browser", func(t *testing.T) {
		server, record := newServer(t)
		opened := []string{}
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		dependencies.IsInteractive = func() bool { return true }
		dependencies.Input = strings.NewReader("y\n")
		dependencies.OpenURL = func(target string) error { opened = append(opened, target); return nil }
		code := Run(context.Background(), []string{"--json", "--host", server.URL, "destroy", "daemon-uuid", "--idempotency-key", "phase2-destroy-key"}, dependencies)
		if code != 6 || len(opened) != 0 || errorOutput.Len() != 0 {
			t.Fatalf("exit = %d, opened = %v, stderr = %q", code, opened, errorOutput.String())
		}
		if !strings.Contains(output.String(), `"code":"confirmation_required"`) || !strings.Contains(output.String(), `"confirmation_id":"confirmation-uuid"`) {
			t.Fatalf("stdout = %q", output.String())
		}
		if n := len(record.requests); record.requests[n-1] != "DELETE /api/v1/daemons/daemon-uuid" || n != 3 {
			t.Fatalf("requests = %v", record.requests)
		}
	})

	t.Run("interactive offers to open the approval url and does not resubmit", func(t *testing.T) {
		server, record := newServer(t)
		opened := []string{}
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		dependencies.IsInteractive = func() bool { return true }
		dependencies.Input = strings.NewReader("y\n")
		dependencies.OpenURL = func(target string) error { opened = append(opened, target); return nil }
		code := Run(context.Background(), []string{"--host", server.URL, "destroy", "daemon-uuid", "--idempotency-key", "phase2-destroy-key"}, dependencies)
		if code != 6 || !slices.Equal(opened, []string{"https://daemons.run/settings?tab=control-plane"}) {
			t.Fatalf("exit = %d, opened = %v, stderr = %q", code, opened, errorOutput.String())
		}
		stderr := errorOutput.String()
		for _, fragment := range []string{"https://daemons.run/settings?tab=control-plane", "2026-09-01T12:00:00+00:00", "confirmation-uuid", "run this command again"} {
			if !strings.Contains(stderr, fragment) {
				t.Fatalf("stderr = %q missing %q", stderr, fragment)
			}
		}
		if output.Len() != 0 || len(record.requests) != 3 {
			t.Fatalf("stdout = %q, requests = %v", output.String(), record.requests)
		}
	})

	t.Run("non-interactive never prompts or opens", func(t *testing.T) {
		server, _ := newServer(t)
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		dependencies.Input = strings.NewReader("y\n")
		dependencies.OpenURL = func(string) error { t.Fatal("browser opened non-interactively"); return nil }
		code := Run(context.Background(), []string{"--host", server.URL, "destroy", "daemon-uuid", "--idempotency-key", "phase2-destroy-key"}, dependencies)
		if code != 6 || strings.Contains(errorOutput.String(), "[y/N]") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})
}

func TestDestroyPreconditionFailedRefetchesAndDoesNotResubmit(t *testing.T) {
	server, record := newPhaseTwoServer(t, func(record *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodGet {
			writer.Header().Set("ETag", `"etag-`+itoa(len(record.requests))+`"`)
			io.WriteString(writer, strings.Replace(daemonResponse, `"status":"running"`, `"status":"stopped"`, 1))
			return
		}
		problem(writer, 412, "precondition_failed", "The daemon changed before this deletion.", `{}`)
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	code := Run(context.Background(), []string{"--host", server.URL, "destroy", "daemon-uuid", "--idempotency-key", "phase2-destroy-key"}, dependencies)
	want := []string{"GET /api/v1/daemons/daemon-uuid", "GET /api/v1", "DELETE /api/v1/daemons/daemon-uuid", "GET /api/v1/daemons/daemon-uuid"}
	if code != 1 || !slices.Equal(record.requests, want) {
		t.Fatalf("exit = %d, requests = %v", code, record.requests)
	}
	stderr := errorOutput.String()
	if !strings.Contains(stderr, "precondition_failed") || !strings.Contains(stderr, "Nothing was destroyed") || !strings.Contains(stderr, "is now stopped") {
		t.Fatalf("stderr = %q", stderr)
	}
}

func TestWaitFlagPollsToTerminalState(t *testing.T) {
	polls := 0
	running := `{"data":{"id":"operation-uuid","type":"daemon.spawn","status":"running","result":[],"retryable":false},"meta":[]}`
	succeeded := `{"data":{"id":"operation-uuid","type":"daemon.spawn","status":"succeeded","result":{"daemon_status":"running"},"retryable":false},"meta":[]}`
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		switch {
		case request.Method == http.MethodPost:
			writer.WriteHeader(http.StatusAccepted)
			io.WriteString(writer, spawnResponse)
		case strings.HasPrefix(request.URL.Path, "/api/v1/operations/"):
			polls++
			if polls < 3 {
				writer.Header().Set("Retry-After", "4")
				io.WriteString(writer, running)
				return
			}
			io.WriteString(writer, succeeded)
		default:
			http.NotFound(writer, request)
		}
	})

	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	sleeps := []time.Duration{}
	dependencies.Sleep = func(_ context.Context, duration time.Duration) error { sleeps = append(sleeps, duration); return nil }
	code := Run(context.Background(), []string{"--json", "--host", server.URL, "spawn", "research", "--server", "11111111-2222-3333-4444-555555555555", "--wait", "--idempotency-key", "phase2-spawn-key"}, dependencies)
	if code != 0 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
	}
	if output.String() != spawnResponse+"\n"+succeeded+"\n" {
		t.Fatalf("stdout = %q", output.String())
	}
	if polls != 3 || len(sleeps) != 3 || sleeps[1] != 4*time.Second || sleeps[2] != 4*time.Second {
		t.Fatalf("polls = %d, sleeps = %v", polls, sleeps)
	}
	if !strings.Contains(errorOutput.String(), "Waiting for operation operation-uuid") || !strings.Contains(errorOutput.String(), "operation-uuid: running") {
		t.Fatalf("stderr = %q", errorOutput.String())
	}
	if !strings.Contains(record.requests[len(record.requests)-1], "GET /api/v1/operations/operation-uuid") {
		t.Fatalf("requests = %v", record.requests)
	}
}

func TestJSONWaitPollFailureDoesNotDuplicateInitialDocument(t *testing.T) {
	invalidPoll := `{"data":{"id":"operation-uuid","type":"daemon.spawn","result":[]},"meta":[]}`
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			writer.WriteHeader(http.StatusAccepted)
			_, _ = io.WriteString(writer, spawnResponse)
			return
		}
		_, _ = io.WriteString(writer, invalidPoll)
	})

	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	dependencies.Sleep = func(context.Context, time.Duration) error { return nil }
	code := Run(context.Background(), []string{"--json", "--host", server.URL, "spawn", "research", "--server", "11111111-2222-3333-4444-555555555555", "--wait", "--idempotency-key", "phase2-spawn-key"}, dependencies)
	if code != 1 || strings.Count(output.String(), spawnResponse) != 1 {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
	}

	decoder := json.NewDecoder(strings.NewReader(output.String()))
	var initial, problemDocument map[string]any
	if err := decoder.Decode(&initial); err != nil {
		t.Fatalf("decode initial document: %v", err)
	}
	if err := decoder.Decode(&problemDocument); err != nil {
		t.Fatalf("decode problem document: %v", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		t.Fatalf("unexpected third JSON document: %#v, %v", extra, err)
	}
	if problemDocument["code"] != "invalid_response" || problemDocument["status"] != float64(http.StatusBadGateway) {
		t.Fatalf("problem = %#v", problemDocument)
	}
}

func TestWaitFlagTimeoutIsOutcomeUnknownWithGuidance(t *testing.T) {
	queued := `{"data":{"id":"operation-uuid","type":"daemon.retry","status":"queued","result":{},"retryable":false},"meta":{}}`
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			writer.WriteHeader(http.StatusAccepted)
		}
		io.WriteString(writer, queued)
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	now := time.Unix(0, 0)
	dependencies.Now = func() time.Time { return now }
	dependencies.Sleep = func(_ context.Context, duration time.Duration) error { now = now.Add(duration); return nil }
	code := Run(context.Background(), []string{"--host", server.URL, "retry", "daemon-uuid", "--wait", "--wait-timeout", "9s", "--idempotency-key", "phase2-retry-key"}, dependencies)
	if code != 8 {
		t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
	}
	stderr := errorOutput.String()
	for _, fragment := range []string{"wait_timeout", "daemons operations show operation-uuid", "daemons show daemon-uuid", "phase2-retry-key", "Never retry under a new idempotency key"} {
		if !strings.Contains(stderr, fragment) {
			t.Fatalf("stderr = %q missing %q", stderr, fragment)
		}
	}
	if strings.Count(output.String(), "Operation operation-uuid: queued") != 2 {
		t.Fatalf("stdout = %q", output.String())
	}
}

func TestWaitFlagPartialSuccessIsVisibleFailure(t *testing.T) {
	queued := `{"data":{"id":"operation-uuid","type":"daemon.start","status":"queued","result":{},"retryable":false},"meta":{}}`
	partial := `{"data":{"id":"operation-uuid","type":"daemon.start","status":"partially_succeeded","result":{"daemon_status":"error"},"error_code":"agent_install_failed","retryable":true},"meta":{}}`
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		if request.Method == http.MethodPost {
			writer.WriteHeader(http.StatusAccepted)
			io.WriteString(writer, queued)
			return
		}
		io.WriteString(writer, partial)
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	dependencies.Sleep = func(context.Context, time.Duration) error { return nil }
	code := Run(context.Background(), []string{"--host", server.URL, "start", "daemon-uuid", "--wait", "--idempotency-key", "phase2-start-key"}, dependencies)
	if code != 1 || !strings.Contains(errorOutput.String(), "agent_install_failed") || !strings.Contains(errorOutput.String(), "only partly succeeded") {
		t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
	}
	if !strings.Contains(output.String(), "partially_succeeded") || !strings.Contains(output.String(), "result.daemon_status: error") {
		t.Fatalf("stdout = %q", output.String())
	}
}

func TestSpawnTransportFailureAfterDispatchIsOutcomeUnknown(t *testing.T) {
	server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
		hijacker, ok := writer.(http.Hijacker)
		if !ok {
			t.Fatal("hijack unsupported")
		}
		connection, _, err := hijacker.Hijack()
		if err != nil {
			t.Fatal(err)
		}
		connection.Close()
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	code := Run(context.Background(), []string{"--host", server.URL, "spawn", "research", "--server", "11111111-2222-3333-4444-555555555555", "--idempotency-key", "phase2-spawn-key"}, dependencies)
	// Go's transport may replay a request carrying Idempotency-Key once when a
	// reused connection dies before any response; that replay must carry the
	// identical key, and the CLI itself never submits under a new one.
	if code != 8 || len(record.requests) < 2 || len(record.requests) > 3 {
		t.Fatalf("exit = %d, requests = %v, stderr = %q", code, record.requests, errorOutput.String())
	}
	for index, request := range record.requests {
		if strings.HasPrefix(request, "POST") && record.headers[index].Get("Idempotency-Key") != "phase2-spawn-key" {
			t.Fatalf("request %d replayed under a different key: %v", index, record.headers[index])
		}
	}
	stderr := errorOutput.String()
	for _, fragment := range []string{"outcome_unknown", "daemons list", "--idempotency-key phase2-spawn-key", "Never retry under a new idempotency key"} {
		if !strings.Contains(stderr, fragment) {
			t.Fatalf("stderr = %q missing %q", stderr, fragment)
		}
	}
}

func TestOperationsListHumanTable(t *testing.T) {
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, `{"data":[{"id":"operation-uuid","type":"daemon.start","status":"succeeded","resource":{"type":"daemon","id":"daemon-uuid"},"result":{},"retryable":false,"updated_at":"2026-09-01T10:00:00+00:00"},{"id":"other","type":"daemon.destroy","status":"failed","resource":null,"result":{},"retryable":false}],"meta":{"next_cursor":null}}`)
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	if code := Run(context.Background(), []string{"--host", server.URL, "operations", "list"}, dependencies); code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 3 || !strings.HasPrefix(lines[0], "ID") || !strings.Contains(lines[1], "daemon daemon-uuid") || !strings.Contains(lines[2], "-") {
		t.Fatalf("stdout = %q", output.String())
	}
}
