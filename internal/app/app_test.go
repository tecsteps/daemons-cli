package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
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
			io.WriteString(writer, `{"data":{"device_code":"DEVICE-CODE","verification_url":"https://example.test/approve","expires_at":"2030-01-01T00:00:00Z","interval_seconds":5},"meta":{}}`)
		case "/api/v1/device-authorizations/DEVICE-CODE":
			io.WriteString(writer, `{"data":{"status":"approved","access_token":"dr_cp_login_token","token_type":"Bearer"},"meta":{}}`)
		case "/api/v1/me":
			if request.Header.Get("Authorization") != "Bearer dr_cp_login_token" {
				t.Errorf("me authorization = %q", request.Header.Get("Authorization"))
			}
			io.WriteString(writer, `{"data":{"account":{"id":"user-uuid","email":"developer@example.test","control_plane_api_enabled":true},"token":{"id":"token-uuid","name":"CLI","scopes":[],"expires_at":"2030-01-01T00:00:00Z"}},"meta":{}}`)
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
	dependencies := Dependencies{
		Output:      &output,
		ErrorOutput: &errorOutput,
		Environment: environment,
		HTTPClient:  server.Client(),
		Now:         now,
		Sleep:       noWait,
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
	if scopes := <-requestedScopes; len(scopes) != 7 {
		t.Fatalf("default scopes = %#v", scopes)
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
	if requests != 3 {
		t.Fatalf("requests = %d, want daemon resolution, version preflight, and upload", requests)
	}

	requests = 0
	output.Reset()
	errorOutput.Reset()
	code = Run(context.Background(), []string{"--base-url", server.URL, "upload", "research", filepath.Join(directory, "missing")}, dependencies)
	if code != 1 || requests != 0 {
		t.Fatalf("invalid upload exit=%d requests=%d", code, requests)
	}
}
