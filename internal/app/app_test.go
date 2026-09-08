package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/tecsteps/daemons-cli/internal/credentials"
)

func TestLoginWhoamiListAndLogout(t *testing.T) {
	requestedScopes := make(chan []string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch request.URL.Path {
		case "/api/v1/device-authorizations":
			var body struct {
				Scopes []string `json:"scopes"`
			}
			json.NewDecoder(request.Body).Decode(&body)
			requestedScopes <- body.Scopes
			writer.WriteHeader(http.StatusCreated)
			io.WriteString(writer, `{"data":{"device_code":"DEVICE-CODE","verification_url":"https://example.test/approve","expires_at":"2030-01-01T00:00:00Z","interval_seconds":5},"meta":[]}`)
		case "/api/v1/device-authorizations/DEVICE-CODE":
			io.WriteString(writer, `{"data":{"status":"approved","access_token":"dr_cp_login_token","token_type":"Bearer"},"meta":[]}`)
		case "/api/v1/me":
			if request.Header.Get("Authorization") != "Bearer dr_cp_login_token" {
				t.Errorf("me authorization = %q", request.Header.Get("Authorization"))
			}
			io.WriteString(writer, `{"data":{"account":{"id":"user-uuid","email":"developer@example.test","control_plane_api_enabled":true},"token":{"id":"token-uuid","name":"CLI","scopes":[],"restrictions":[],"expires_at":"2030-01-01T00:00:00Z"}},"meta":[]}`)
		case "/api/v1/daemons":
			io.WriteString(writer, `{"data":[{"id":"daemon-uuid","name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"}}],"meta":{}}`)
		case "/api/v1/tokens/current":
			if request.Method != http.MethodDelete || request.Header.Get("Idempotency-Key") == "" {
				t.Errorf("logout request method=%s idempotency=%q", request.Method, request.Header.Get("Idempotency-Key"))
			}
			io.WriteString(writer, `{"data":{"revoked":true},"meta":{}}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credentials.json")
	environment := map[string]string{"HOME": directory, "TERM": "xterm-256color"}
	now := func() time.Time { return time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC) }
	noWait := func(context.Context, time.Duration) error { return nil }

	var output bytes.Buffer
	var errorOutput bytes.Buffer
	opened := []string{}
	dependencies := Dependencies{
		Output:      &output,
		ErrorOutput: &errorOutput,
		Environment: environment,
		HTTPClient:  server.Client(),
		Now:         now,
		Sleep:       noWait,
		IsInteractive: func() bool {
			return true
		},
		OpenURL: func(target string) error {
			opened = append(opened, target)
			return nil
		},
	}
	baseArguments := []string{"--base-url", server.URL, "--credentials-file", credentialPath}
	if code := Run(context.Background(), append(baseArguments, "login"), dependencies); code != 0 {
		t.Fatalf("login exit = %d, stderr = %s", code, errorOutput.String())
	}
	if strings.Contains(output.String(), "dr_cp_login_token") {
		t.Fatal("login output exposed the token")
	}
	credential, err := (credentials.Store{Path: credentialPath}).Load(normalizedHost(t, server.URL))
	if err != nil {
		t.Fatal(err)
	}
	if credential.Token != "dr_cp_login_token" || credential.AccountEmail != "developer@example.test" {
		t.Fatalf("credential = %#v", credential)
	}
	if scopes := <-requestedScopes; !slices.Equal(scopes, defaultScopes) || len(scopes) != 16 {
		t.Fatalf("default scopes = %#v", scopes)
	}
	if !slices.Equal(opened, []string{"https://example.test/approve"}) || !strings.Contains(output.String(), "https://example.test/approve") {
		t.Fatalf("opened = %#v, stdout = %q", opened, output.String())
	}

	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), append(baseArguments, "whoami"), dependencies); code != 0 || output.String() != "developer@example.test\n" {
		t.Fatalf("whoami exit=%d stdout=%q stderr=%q", code, output.String(), errorOutput.String())
	}

	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), append(baseArguments, "daemons", "list"), dependencies); code != 0 || !strings.Contains(output.String(), "research") || !strings.Contains(output.String(), "ready") {
		t.Fatalf("list exit=%d stdout=%q stderr=%q", code, output.String(), errorOutput.String())
	}

	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), append(baseArguments, "logout"), dependencies); code != 0 {
		t.Fatalf("logout exit=%d stdout=%q stderr=%q", code, output.String(), errorOutput.String())
	}
	if _, err := os.Stat(credentialPath); !os.IsNotExist(err) {
		t.Fatalf("credential file still exists: %v", err)
	}
}

func TestLoginDeviceFlowPolling(t *testing.T) {
	tests := []struct {
		name          string
		pollResponses []string
		expiresAt     string
		wantExit      int
		wantCode      string
		wantIntervals []time.Duration
	}{
		{
			name:          "pending continues polling",
			pollResponses: []string{"pending", "approved"},
			expiresAt:     "2030-01-01T00:00:00Z",
			wantIntervals: []time.Duration{5 * time.Second, 5 * time.Second},
		},
		{
			name:          "slow down grows the interval",
			pollResponses: []string{"slow_down", "approved"},
			expiresAt:     "2030-01-01T00:00:00Z",
			wantIntervals: []time.Duration{5 * time.Second, 10 * time.Second},
		},
		{
			name:          "authorization rejected exits with authentication failure",
			pollResponses: []string{"authorization_rejected"},
			expiresAt:     "2030-01-01T00:00:00Z",
			wantExit:      3,
			wantCode:      "authorization_rejected",
			wantIntervals: []time.Duration{5 * time.Second},
		},
		{
			name:          "authorization expired exits with authentication failure",
			pollResponses: []string{"authorization_expired"},
			expiresAt:     "2030-01-01T00:00:00Z",
			wantExit:      3,
			wantCode:      "authorization_expired",
			wantIntervals: []time.Duration{5 * time.Second},
		},
		{
			name:          "unknown status is invalid",
			pollResponses: []string{"unknown"},
			expiresAt:     "2030-01-01T00:00:00Z",
			wantExit:      1,
			wantCode:      "invalid_device_authorization",
			wantIntervals: []time.Duration{5 * time.Second},
		},
		{
			name:      "outer expiry exits with authentication failure",
			expiresAt: "2029-01-01T00:00:00Z",
			wantExit:  3,
			wantCode:  "authorization_expired",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			polls := 0
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				writer.Header().Set("Content-Type", "application/json")
				switch request.URL.Path {
				case "/api/v1/device-authorizations":
					writer.WriteHeader(http.StatusCreated)
					fmt.Fprintf(writer, `{"data":{"device_code":"DEVICE-CODE","verification_url":"https://example.test/approve","expires_at":"%s","interval_seconds":5},"meta":[]}`, test.expiresAt)
				case "/api/v1/device-authorizations/DEVICE-CODE":
					response := test.pollResponses[polls]
					polls++
					switch response {
					case "slow_down", "authorization_rejected", "authorization_expired":
						problem(writer, http.StatusBadRequest, response, "Device authorization was not approved.", `{}`)
					case "approved":
						io.WriteString(writer, `{"data":{"status":"approved","access_token":"dr_cp_login_token","token_type":"Bearer"},"meta":[]}`)
					default:
						fmt.Fprintf(writer, `{"data":{"status":"%s"},"meta":[]}`, response)
					}
				case "/api/v1/me":
					io.WriteString(writer, `{"data":{"account":{"id":"user-uuid","email":"developer@example.test","control_plane_api_enabled":true},"token":{"id":"token-uuid","name":"CLI","scopes":[],"restrictions":[],"expires_at":"2030-01-01T00:00:00Z"}},"meta":[]}`)
				default:
					http.NotFound(writer, request)
				}
			}))
			defer server.Close()

			var output bytes.Buffer
			var errorOutput bytes.Buffer
			intervals := []time.Duration{}
			dependencies := Dependencies{
				Output:      &output,
				ErrorOutput: &errorOutput,
				Environment: map[string]string{"HOME": t.TempDir()},
				HTTPClient:  server.Client(),
				Now:         func() time.Time { return time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC) },
				Sleep: func(_ context.Context, interval time.Duration) error {
					intervals = append(intervals, interval)
					return nil
				},
				IsInteractive: func() bool { return false },
			}
			code := Run(context.Background(), []string{"--host", server.URL, "login"}, dependencies)
			if code != test.wantExit {
				t.Fatalf("exit = %d, want %d; stdout = %q; stderr = %q", code, test.wantExit, output.String(), errorOutput.String())
			}
			if !slices.Equal(intervals, test.wantIntervals) {
				t.Fatalf("intervals = %v, want %v", intervals, test.wantIntervals)
			}
			if test.wantCode != "" && !strings.Contains(errorOutput.String(), test.wantCode) {
				t.Fatalf("stderr = %q, want code %q", errorOutput.String(), test.wantCode)
			}
		})
	}
}

func TestUploadValidatesLocallyThenUsesCanonicalEndpoint(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		requests++
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch request.URL.Path {
		case "/api/v1":
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
		case "/api/v1/daemons":
			io.WriteString(writer, `{"data":[{"id":"daemon-uuid","name":"research","status":"running","primary_agent":"codex","server":{"name":"host"}}],"meta":{}}`)
		case "/api/v1/daemons/daemon-uuid/files":
			if request.Method == http.MethodGet {
				// The pre-upload overwrite check reads the upload folder.
				io.WriteString(writer, `{"data":[],"meta":{"next_cursor":null}}`)
				return
			}
			if err := request.ParseMultipartForm(11 << 20); err != nil {
				t.Errorf("ParseMultipartForm() = %v", err)
			}
			file, _, err := request.FormFile("file")
			if err != nil {
				t.Errorf("FormFile() = %v", err)
			}
			contents, _ := io.ReadAll(file)
			if string(contents) != "upload body" {
				t.Errorf("upload body = %q", contents)
			}
			io.WriteString(writer, `{"ok":true,"path":"/root/workspace/uploads/note.txt"}`)
		default:
			http.NotFound(writer, request)
		}
	}))
	defer server.Close()

	directory := t.TempDir()
	filePath := filepath.Join(directory, "note.txt")
	if err := os.WriteFile(filePath, []byte("upload body"), 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	dependencies := Dependencies{
		Output:      &output,
		ErrorOutput: &errorOutput,
		Environment: map[string]string{"HOME": directory, "DAEMONS_TOKEN": "dr_cp_test"},
		HTTPClient:  server.Client(),
	}
	code := Run(context.Background(), []string{"--base-url", server.URL, "upload", "research", filePath}, dependencies)
	if code != 0 || output.String() != "/root/workspace/uploads/note.txt\n" {
		t.Fatalf("upload exit=%d stdout=%q stderr=%q", code, output.String(), errorOutput.String())
	}
	if requests != 4 {
		t.Fatalf("requests = %d, want daemon resolution, version preflight, the overwrite check, and upload", requests)
	}

	requests = 0
	output.Reset()
	errorOutput.Reset()
	code = Run(context.Background(), []string{"--base-url", server.URL, "upload", "research", filepath.Join(directory, "missing")}, dependencies)
	if code != 1 || requests != 0 {
		t.Fatalf("invalid upload exit=%d requests=%d", code, requests)
	}
}
