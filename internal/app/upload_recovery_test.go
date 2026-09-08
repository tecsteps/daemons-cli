package app

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/tecsteps/daemons-cli/internal/upload"
)

const recoveryDaemon = "11111111-2222-4333-8444-555555555555"

type accessCall struct {
	action string
	method string
	suffix string
	body   string
}

// accessWorkspaceServer is a v2 workspace-access fake. It records the exact
// ticket action, HTTP method, gateway suffix and request body of every relay
// call so a test can assert the wire contract rather than the printed text.
type accessWorkspaceServer struct {
	mu      sync.Mutex
	calls   []accessCall
	uploads int
	// receiptQueue hands out one receipt per recovery read, oldest first.
	receiptQueue []string
	// hijack drops the connection on the nth upload to force an ambiguous outcome.
	hijack int
	// listing is the guest reply to the pre-upload collision read.
	listing string
}

func newAccessWorkspaceServer(t *testing.T, server *accessWorkspaceServer) (*httptest.Server, Dependencies, *bytes.Buffer, *bytes.Buffer, string) {
	t.Helper()
	handler := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch {
		case r.URL.Path == "/api/v1":
			io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
			return
		case r.URL.Path == "/api/v1/daemons" || r.URL.Path == "/api/v1/daemons/"+recoveryDaemon:
			io.WriteString(w, `{"data":[{"id":"`+recoveryDaemon+`","name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"}}],"meta":{}}`)
			return
		case r.URL.Path == "/api/v1/daemons/"+recoveryDaemon+"/access-tickets":
			var metadata map[string]string
			if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
				t.Error(err)
			}
			suffix, method := "/files/query", "POST"
			switch metadata["action"] {
			case "files.upload":
				suffix, method = "/files/uploads/"+metadata["operation_uuid"], "PUT"
			case "files.read":
			default:
				t.Errorf("unexpected ticket action %q", metadata["action"])
			}
			server.mu.Lock()
			server.calls = append(server.calls, accessCall{action: metadata["action"], method: method, suffix: suffix})
			server.mu.Unlock()
			fmt.Fprintf(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"%s","gateway_path":"/v1/workspaces/%s%s"}}`, method, recoveryDaemon, suffix)
			return
		case strings.HasPrefix(r.URL.Path, "/v1/workspaces/"+recoveryDaemon):
			suffix := strings.TrimPrefix(r.URL.Path, "/v1/workspaces/"+recoveryDaemon)
			if r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
				t.Error("relay admission is not ticket bound")
			}
			if strings.HasPrefix(suffix, "/files/uploads/") {
				server.mu.Lock()
				server.uploads++
				count := server.uploads
				server.mu.Unlock()
				var size [4]byte
				io.ReadFull(r.Body, size[:])
				selector := make([]byte, binary.BigEndian.Uint32(size[:]))
				io.ReadFull(r.Body, selector)
				io.Copy(io.Discard, r.Body)
				server.mu.Lock()
				server.calls = append(server.calls, accessCall{action: "files.upload", method: r.Method, suffix: suffix, body: string(selector)})
				server.mu.Unlock()
				if count == server.hijack {
					connection, _, err := w.(http.Hijacker).Hijack()
					if err != nil {
						t.Fatal(err)
					}
					connection.Close()
					return
				}
				io.WriteString(w, `{"status":"applied","path":"/home/dr-agent/workspace/uploads/note.txt","bytes":11,"sha256":"`+strings.Repeat("a", 64)+`"}`)
				return
			}
			raw, _ := io.ReadAll(r.Body)
			server.mu.Lock()
			server.calls = append(server.calls, accessCall{action: "files.read", method: r.Method, suffix: suffix, body: string(raw)})
			server.mu.Unlock()
			var selector map[string]any
			json.Unmarshal(raw, &selector)
			if selector["operation"] == "upload_receipt" {
				io.WriteString(w, server.nextReceipt())
				return
			}
			if server.listing != "" {
				io.WriteString(w, server.listing)
				return
			}
			io.WriteString(w, `{"data":[],"meta":{"next_cursor":null}}`)
			return
		}
		t.Errorf("unexpected endpoint %s", r.URL.Path)
		w.WriteHeader(404)
	}))
	t.Cleanup(handler.Close)
	var output, errorOutput bytes.Buffer
	directory := t.TempDir()
	credentialsFile := filepath.Join(directory, "credentials.json")
	dependencies := Dependencies{
		Output:        &output,
		ErrorOutput:   &errorOutput,
		Environment:   map[string]string{"HOME": directory, "DAEMONS_TOKEN": "dr_cp_test", "DAEMONS_CREDENTIALS_FILE": credentialsFile},
		HTTPClient:    handler.Client(),
		Now:           func() time.Time { return time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC) },
		IsInteractive: func() bool { return false },
	}
	return handler, dependencies, &output, &errorOutput, credentialsFile
}

// receiptQueue lets a test hand out a different receipt per recovery read.
func (s *accessWorkspaceServer) nextReceipt() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.receiptQueue) == 0 {
		return `{"status":"not_found"}`
	}
	next := s.receiptQueue[0]
	s.receiptQueue = s.receiptQueue[1:]
	return next
}

func (s *accessWorkspaceServer) uploadCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.uploads
}

func (s *accessWorkspaceServer) queueReceipts(receipts ...string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receiptQueue = append(s.receiptQueue, receipts...)
}

func (s *accessWorkspaceServer) actions() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := make([]string, 0, len(s.calls))
	for _, call := range s.calls {
		seen = append(seen, call.method+" "+call.suffix+" "+call.action)
	}
	return seen
}

// TestInterruptedUploadStagesItsOperationForRecovery proves the recovery hook:
// the operation identity is on disk before the request, survives an ambiguous
// outcome, and files recover resolves it through a receipt read without ever
// sending the file bytes again.
func TestInterruptedUploadStagesItsOperationForRecovery(t *testing.T) {
	fake := &accessWorkspaceServer{hijack: 1}
	handler, dependencies, output, errorOutput, credentialsFile := newAccessWorkspaceServer(t, fake)
	localFile := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(localFile, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	code := Run(context.Background(), []string{"--host", handler.URL, "upload", recoveryDaemon, localFile}, dependencies)
	if code != 8 {
		t.Fatalf("upload exit = %d, stderr = %q", code, errorOutput.String())
	}
	staging, err := upload.OpenStaging(dependencies.Environment, credentialsFile, recoveryDaemon)
	if err != nil {
		t.Fatal(err)
	}
	pending, err := staging.List()
	if err != nil || len(pending) != 1 || pending[0].Selector != "uploads/note.txt" {
		t.Fatalf("pending = %+v, %v", pending, err)
	}
	operation := pending[0].OperationUUID

	uploadsBefore := fake.uploadCount()
	fake.queueReceipts(`{"status":"applied","path":"uploads/note.txt","bytes":11,"sha256":"` + strings.Repeat("a", 64) + `"}`)
	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), []string{"--host", handler.URL, "files", "recover", recoveryDaemon}, dependencies); code != 0 {
		t.Fatalf("recover exit = %d, stderr = %q", code, errorOutput.String())
	}
	if fake.uploadCount() != uploadsBefore {
		t.Fatalf("recovery replayed the upload: %d uploads", fake.uploadCount())
	}
	if !strings.Contains(output.String(), operation) || !strings.Contains(output.String(), "applied") {
		t.Fatalf("stdout = %q", output.String())
	}
	seen := fake.actions()
	if !strings.Contains(strings.Join(seen, ","), "POST /files/query files.read") {
		t.Fatalf("recovery did not read a receipt through files.read: %v", seen)
	}
	if pending, err := staging.List(); err != nil || len(pending) != 0 {
		t.Fatalf("resolved operation stayed pending: %+v, %v", pending, err)
	}
}

// An unresolved receipt must keep the record and exit 8, so nothing is lost and
// nothing is replayed.
func TestRecoveryKeepsAnUnresolvedOperation(t *testing.T) {
	fake := &accessWorkspaceServer{hijack: 1}
	handler, dependencies, output, _, credentialsFile := newAccessWorkspaceServer(t, fake)
	localFile := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(localFile, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}
	Run(context.Background(), []string{"--host", handler.URL, "upload", recoveryDaemon, localFile}, dependencies)
	fake.queueReceipts(`{"status":"outcome_unknown"}`)
	output.Reset()
	if code := Run(context.Background(), []string{"--host", handler.URL, "files", "recover", recoveryDaemon}, dependencies); code != 8 {
		t.Fatalf("recover exit = %d, stdout = %q", code, output.String())
	}
	staging, _ := upload.OpenStaging(dependencies.Environment, credentialsFile, recoveryDaemon)
	if pending, err := staging.List(); err != nil || len(pending) != 1 {
		t.Fatalf("unresolved operation was dropped: %+v, %v", pending, err)
	}
}
