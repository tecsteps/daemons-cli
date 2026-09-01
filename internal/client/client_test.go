package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func TestNormalizeBaseURL(t *testing.T) {
	tests := map[string]string{
		"origin":       "https://control.example/api/v1",
		"existing api": "https://control.example/api/v1",
		"loopback":     "http://127.0.0.1:8080/api/v1",
	}
	inputs := map[string]string{
		"origin":       "https://control.example/",
		"existing api": "https://control.example/api/v1",
		"loopback":     "http://127.0.0.1:8080",
	}
	for name, want := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := NormalizeBaseURL(inputs[name])
			if err != nil || got != want {
				t.Fatalf("NormalizeBaseURL() = %q, %v, want %q", got, err, want)
			}
		})
	}

	for _, invalid := range []string{"http://example.test", "https://user@example.test", "https://example.test?q=1"} {
		if _, err := NormalizeBaseURL(invalid); err == nil {
			t.Fatalf("NormalizeBaseURL(%q) succeeded", invalid)
		}
	}
}

func TestListDaemonsSendsAuthenticationAndVersionHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/api/v1/daemons" {
			t.Errorf("path = %s", request.URL.Path)
		}
		if request.Header.Get("Authorization") != "Bearer dr_cp_test" {
			t.Errorf("authorization = %s", request.Header.Get("Authorization"))
		}
		if request.Header.Get("User-Agent") != "daemons/0.1.0" || request.Header.Get("X-Daemons-CLI-Version") != "0.1.0" {
			t.Errorf("version headers were not sent")
		}
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"data":[{"id":"uuid","name":"research","status":"running","primary_agent":"codex","server":{"name":"host"}}],"meta":{}}`)
	}))
	defer server.Close()

	client, err := New(server.URL, "dr_cp_test", WithVersion("0.1.0"))
	if err != nil {
		t.Fatal(err)
	}
	result, err := client.ListDaemons(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Data) != 1 || result.Data[0].Name != "research" {
		t.Fatalf("ListDaemons() = %#v", result)
	}
}

func TestAPIErrorPreservesClassification(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.WriteHeader(http.StatusForbidden)
		json.NewEncoder(writer).Encode(map[string]any{"code": "scope_denied", "detail": "Scope denied."})
	}))
	defer server.Close()

	client, _ := New(server.URL, "dr_cp_test")
	_, err := client.ListDaemons(context.Background())
	if !IsAPIError(err, "scope_denied") {
		t.Fatalf("ListDaemons() error = %v", err)
	}
}

func TestUploadStreamsTheOpenFileDescriptor(t *testing.T) {
	temporary := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(temporary, []byte("same descriptor"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(temporary)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		if request.URL.Path == "/api/v1" {
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
			return
		}
		if request.URL.Path != "/api/v1/daemons/daemon-id/files" {
			t.Errorf("path = %s", request.URL.Path)
		}
		if err := request.ParseMultipartForm(11 << 20); err != nil {
			t.Errorf("ParseMultipartForm() error = %v", err)
		}
		part, _, err := request.FormFile("file")
		if err != nil {
			t.Errorf("FormFile() error = %v", err)
		}
		contents, _ := io.ReadAll(part)
		if string(contents) != "same descriptor" {
			t.Errorf("contents = %q", contents)
		}
		io.WriteString(writer, `{"ok":true,"path":"/root/workspace/uploads/note.txt"}`)
	}))
	defer server.Close()

	client, _ := New(server.URL, "dr_cp_test")
	result, err := client.Upload(context.Background(), "daemon-id", "note.txt", file)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || !strings.HasSuffix(result.Path, "/note.txt") {
		t.Fatalf("Upload() = %#v", result)
	}
}

func TestUploadMapsAuthoritativeSizeRejectionToExitSeven(t *testing.T) {
	filePath := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(filePath, []byte("body"), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(filePath)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()

	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/api/v1" {
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
			return
		}
		writer.Header().Set("Content-Type", "application/problem+json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		writer.WriteHeader(http.StatusUnprocessableEntity)
		io.WriteString(writer, `{"code":"validation_failed","detail":"One or more fields are invalid.","errors":{"file":["Files must be 10 MB or smaller."]}}`)
	}))
	defer server.Close()

	api, _ := New(server.URL, "dr_cp_test")
	_, err = api.Upload(context.Background(), "daemon-id", "note.txt", file)
	if errs.ExitCode(err) != 7 || err.Error() != "Files must be 10 MB or smaller." {
		t.Fatalf("Upload() error = %v, exit = %d", err, errs.ExitCode(err))
	}
}
