package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

func TestPhaseOneCommandsPreserveCanonicalJSON(t *testing.T) {
	operation := `{"data":{"id":"operation-uuid","type":"daemon.lifecycle","status":"succeeded","resource":{"type":"daemon","id":"daemon-uuid"},"result":{},"retryable":false,"future_operation_field":"kept"},"meta":{"future_meta":"kept"},"future_envelope":"kept"}`
	tests := []struct {
		name         string
		arguments    []string
		method       string
		path         string
		response     string
		mutation     bool
		operationKey string
	}{
		{
			name:      "capabilities",
			arguments: []string{"capabilities"},
			method:    http.MethodGet,
			path:      "/api/v1/capabilities",
			response:  `{"data":[{"name":"servers","enabled":true,"reason":null,"dependencies":["servers:read"],"future_capability_field":"kept"}],"meta":[],"future_envelope":"kept"}`,
		},
		{
			name:      "servers list",
			arguments: []string{"servers", "list"},
			method:    http.MethodGet,
			path:      "/api/v1/servers",
			response:  `{"data":[{"id":"server-uuid","name":"host","status":"running","region":"fsn1","capacity":{"cores":4,"memory_gb":8,"disk_gb":80,"daemon_count":1,"eligible_for_daemon":true},"future_server_field":"kept"}],"meta":{"next_cursor":null},"future_envelope":"kept"}`,
		},
		{
			name:      "servers show",
			arguments: []string{"servers", "show", "server-uuid"},
			method:    http.MethodGet,
			path:      "/api/v1/servers/server-uuid",
			response:  `{"data":{"id":"server-uuid","name":"host","status":"running","region":"fsn1","capacity":{"cores":4,"memory_gb":"8.00","disk_gb":80,"daemon_count":1,"eligible_for_daemon":true},"future_server_field":"kept"},"meta":[],"future_envelope":"kept"}`,
		},
		{
			name:      "daemons show",
			arguments: []string{"daemons", "show", "daemon-uuid"},
			method:    http.MethodGet,
			path:      "/api/v1/daemons/daemon-uuid",
			response:  `{"data":{"id":"daemon-uuid","name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"},"future_daemon_field":"kept"},"meta":[],"future_envelope":"kept"}`,
		},
		{
			name:         "daemons start",
			arguments:    []string{"daemons", "start", "daemon-uuid", "--idempotency-key", "phase1-start-key"},
			method:       http.MethodPost,
			path:         "/api/v1/daemons/daemon-uuid/start",
			response:     operation,
			mutation:     true,
			operationKey: "phase1-start-key",
		},
		{
			name:         "daemons stop",
			arguments:    []string{"daemons", "stop", "daemon-uuid", "--idempotency-key", "phase1-stop-key"},
			method:       http.MethodPost,
			path:         "/api/v1/daemons/daemon-uuid/stop",
			response:     operation,
			mutation:     true,
			operationKey: "phase1-stop-key",
		},
		{
			name:         "daemons restart",
			arguments:    []string{"daemons", "restart", "daemon-uuid", "--idempotency-key", "phase1-restart-key"},
			method:       http.MethodPost,
			path:         "/api/v1/daemons/daemon-uuid/restart",
			response:     operation,
			mutation:     true,
			operationKey: "phase1-restart-key",
		},
		{
			name:      "operations show",
			arguments: []string{"operations", "show", "operation-uuid"},
			method:    http.MethodGet,
			path:      "/api/v1/operations/operation-uuid",
			response:  operation,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests := make([]string, 0, 2)
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				requests = append(requests, request.Method+" "+request.URL.Path)
				if request.Header.Get("Authorization") != "Bearer dr_cp_phase1" {
					t.Errorf("Authorization = %q", request.Header.Get("Authorization"))
				}
				if request.Header.Get("User-Agent") != "daemons/v0.2.0-test" || request.Header.Get("X-Daemons-CLI-Version") != "v0.2.0-test" {
					t.Errorf("version headers = %q, %q", request.Header.Get("User-Agent"), request.Header.Get("X-Daemons-CLI-Version"))
				}
				if request.Header.Get("X-Request-Id") != "phase1-request" {
					t.Errorf("X-Request-Id = %q", request.Header.Get("X-Request-Id"))
				}
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("X-Daemons-Api-Version", "v1")
				if request.URL.Path == "/api/v1" {
					io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
					return
				}
				if request.Method != test.method || request.URL.Path != test.path {
					t.Errorf("request = %s %s, want %s %s", request.Method, request.URL.Path, test.method, test.path)
					http.NotFound(writer, request)
					return
				}
				if request.Header.Get("Idempotency-Key") != test.operationKey {
					t.Errorf("Idempotency-Key = %q, want %q", request.Header.Get("Idempotency-Key"), test.operationKey)
				}
				io.WriteString(writer, test.response)
			}))
			defer server.Close()

			var output bytes.Buffer
			var errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			arguments := []string{"--json", "--host", server.URL, "--request-id", "phase1-request"}
			arguments = append(arguments, test.arguments...)
			if code := Run(context.Background(), arguments, dependencies); code != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
			}
			if output.String() != test.response+"\n" {
				t.Fatalf("stdout = %q, want canonical response %q", output.String(), test.response+"\n")
			}
			if errorOutput.Len() != 0 {
				t.Fatalf("stderr = %q", errorOutput.String())
			}
			wantRequests := []string{test.method + " " + test.path}
			if test.mutation {
				wantRequests = append([]string{http.MethodGet + " /api/v1"}, wantRequests...)
			}
			if !slices.Equal(requests, wantRequests) {
				t.Fatalf("requests = %#v, want %#v", requests, wantRequests)
			}
		})
	}
}

func TestLifecycleIdempotencyRequirementsAndGeneration(t *testing.T) {
	t.Run("non-interactive requires an explicit key", func(t *testing.T) {
		requests := 0
		server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
			requests++
		}))
		defer server.Close()

		var output bytes.Buffer
		var errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "start", "daemon-uuid"}, dependencies)
		if code != 2 || requests != 0 {
			t.Fatalf("exit = %d, requests = %d, stderr = %q", code, requests, errorOutput.String())
		}
	})

	t.Run("interactive generation is printed once and forwarded", func(t *testing.T) {
		generated := 0
		mutationKey := ""
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			if request.URL.Path == "/api/v1" {
				io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
				return
			}
			mutationKey = request.Header.Get("Idempotency-Key")
			io.WriteString(writer, `{"data":{"id":"operation-uuid","type":"daemon.start","status":"succeeded","result":{},"retryable":false},"meta":{}}`)
		}))
		defer server.Close()

		var output bytes.Buffer
		var errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		dependencies.IsInteractive = func() bool { return true }
		dependencies.NewIdempotencyKey = func() (string, error) {
			generated++
			return "generated-phase1-key", nil
		}
		code := Run(context.Background(), []string{"--host", server.URL, "start", "daemon-uuid"}, dependencies)
		if code != 0 || generated != 1 || mutationKey != "generated-phase1-key" {
			t.Fatalf("exit = %d, generated = %d, mutation key = %q", code, generated, mutationKey)
		}
		if strings.Count(errorOutput.String(), "generated-phase1-key") != 1 {
			t.Fatalf("stderr = %q", errorOutput.String())
		}
	})
}

func TestVersionMismatchStopsLifecycleMutation(t *testing.T) {
	mutationRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1" {
			mutationRequests++
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v2")
		io.WriteString(writer, `{"data":{"version":"v2"},"meta":{}}`)
	}))
	defer server.Close()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	code := Run(context.Background(), []string{"--host", server.URL, "start", "daemon-uuid", "--idempotency-key", "version-test-key"}, dependencies)
	if code != 2 || mutationRequests != 0 || !strings.Contains(errorOutput.String(), "api_version_mismatch") {
		t.Fatalf("exit = %d, mutation requests = %d, stderr = %q", code, mutationRequests, errorOutput.String())
	}
}

func TestLogoutSkipsDiscoveryPreflight(t *testing.T) {
	requests := make([]string, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests = append(requests, request.Method+" "+request.URL.Path)
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		io.WriteString(writer, `{"data":{"revoked":true},"meta":{}}`)
	}))
	defer server.Close()

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	dependencies.NewIdempotencyKey = func() (string, error) { return "logout-test-key", nil }
	code := Run(context.Background(), []string{"--json", "--host", server.URL, "logout"}, dependencies)
	if code != 0 || !slices.Equal(requests, []string{"DELETE /api/v1/tokens/current"}) {
		t.Fatalf("exit = %d, requests = %#v, stdout = %q, stderr = %q", code, requests, output.String(), errorOutput.String())
	}
}

func TestOperationTerminalStatesControlExitWithoutReplacingJSON(t *testing.T) {
	tests := map[string]int{
		"failed":          1,
		"outcome_unknown": 8,
	}
	for status, wantCode := range tests {
		t.Run(status, func(t *testing.T) {
			response := `{"data":{"id":"operation-uuid","type":"daemon.start","status":"` + status + `","result":{},"retryable":false},"meta":{}}`
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				writer.Header().Set("X-Daemons-Api-Version", "v1")
				io.WriteString(writer, response)
			}))
			defer server.Close()

			var output bytes.Buffer
			var errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			code := Run(context.Background(), []string{"--json", "--host", server.URL, "operations", "show", "operation-uuid"}, dependencies)
			if code != wantCode || output.String() != response+"\n" || errorOutput.Len() != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
			}
		})
	}
}

func TestProblemOutputRedactsSensitiveFieldsAndCredentialPrefixes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.WriteHeader(http.StatusForbidden)
		io.WriteString(writer, `{"status":403,"code":"scope_denied","detail":"Bearer dr_cp_super-secret was denied.","meta":{"access_token":"dr_cp_nested-secret","safe":"kept"}}`)
	}))
	defer server.Close()

	for _, jsonOutput := range []bool{false, true} {
		var output bytes.Buffer
		var errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		arguments := []string{"--host", server.URL, "capabilities"}
		if jsonOutput {
			arguments = append([]string{"--json"}, arguments...)
		}
		if code := Run(context.Background(), arguments, dependencies); code != 5 {
			t.Fatalf("json = %t, exit = %d", jsonOutput, code)
		}
		combined := output.String() + errorOutput.String()
		if strings.Contains(combined, "dr_cp_") || !strings.Contains(combined, "[REDACTED]") {
			t.Fatalf("json = %t, output = %q", jsonOutput, combined)
		}
	}
}

func TestRegistryCommandsProvideHelp(t *testing.T) {
	for name := range commandRegistry {
		t.Run(name, func(t *testing.T) {
			var output bytes.Buffer
			var errorOutput bytes.Buffer
			arguments := append(strings.Fields(name), "--help")
			code := Run(context.Background(), arguments, Dependencies{
				Output:      &output,
				ErrorOutput: &errorOutput,
				Environment: map[string]string{},
			})
			if code != 0 || output.Len() == 0 || errorOutput.Len() != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
			}
		})
	}
}

func TestVersionUsesInjectedDependency(t *testing.T) {
	var output bytes.Buffer
	code := Run(context.Background(), []string{"--version"}, Dependencies{
		Output:      &output,
		ErrorOutput: io.Discard,
		Environment: map[string]string{},
		Version:     "v9.8.7-test",
	})
	if code != 0 || output.String() != "v9.8.7-test\n" {
		t.Fatalf("exit = %d, stdout = %q", code, output.String())
	}
}

func phaseOneDependencies(t *testing.T, httpClient *http.Client, output, errorOutput *bytes.Buffer) Dependencies {
	t.Helper()
	return Dependencies{
		Output:      output,
		ErrorOutput: errorOutput,
		Environment: map[string]string{
			"HOME":          t.TempDir(),
			"DAEMONS_TOKEN": "dr_cp_phase1",
		},
		HTTPClient:    httpClient,
		Version:       "v0.2.0-test",
		IsInteractive: func() bool { return false },
	}
}
