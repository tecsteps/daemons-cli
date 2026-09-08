package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

// accessUploadServer answers the preflight, the ticket mint and the gateway PUT,
// recording the exact action, method, suffix and selector it observed.
type accessUploadServer struct {
	action   string
	method   string
	suffix   string
	selector string
	ticketOp string
	status   int
	body     string
}

func newAccessUploadServer(t *testing.T, record *accessUploadServer) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch {
		case r.URL.Path == "/api/v1":
			io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case strings.HasSuffix(r.URL.Path, "/access-tickets"):
			var metadata map[string]string
			if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
				t.Error(err)
			}
			record.action = metadata["action"]
			record.ticketOp = metadata["operation_uuid"]
			io.WriteString(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"PUT","gateway_path":"/v1/workspaces/`+daemonUUID+`/files/uploads/`+metadata["operation_uuid"]+`"}}`)
		case strings.HasPrefix(r.URL.Path, "/v1/workspaces/"):
			record.method = r.Method
			record.suffix = strings.TrimPrefix(r.URL.Path, "/v1/workspaces/"+daemonUUID)
			var size [4]byte
			if _, err := io.ReadFull(r.Body, size[:]); err != nil {
				t.Error(err)
				return
			}
			selector := make([]byte, binary.BigEndian.Uint32(size[:]))
			io.ReadFull(r.Body, selector)
			record.selector = string(selector)
			io.Copy(io.Discard, r.Body)
			if record.status != 0 {
				w.WriteHeader(record.status)
				return
			}
			io.WriteString(w, record.body)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	api, err := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	return api
}

const daemonUUID = "11111111-2222-4333-8444-555555555555"

func uploadTempFile(t *testing.T, contents string) *os.File {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "upload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { file.Close() })
	if _, err := file.WriteString(contents); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestUploadOperationUsesTheSuppliedIdentityAndConfiguredFolder(t *testing.T) {
	record := &accessUploadServer{body: `{"status":"applied","path":"/srv/workspace/inbox/note.txt","bytes":11,"sha256":"` + strings.Repeat("a", 64) + `"}`}
	api := newAccessUploadServer(t, record)
	paths, err := NewWorkspacePaths(map[string]string{WorkspaceRootVariable: "/srv/workspace", UploadFolderVariable: "inbox"})
	if err != nil {
		t.Fatal(err)
	}
	operation := NewUploadOperationID()
	response, err := api.UploadOperation(context.Background(), daemonUUID, operation, paths, "note.txt", uploadTempFile(t, "hello world"))
	if err != nil {
		t.Fatalf("UploadOperation() = %v", err)
	}
	if record.action != "files.upload" || record.method != http.MethodPut || record.suffix != "/files/uploads/"+operation {
		t.Fatalf("wire = %s %s action=%s", record.method, record.suffix, record.action)
	}
	if record.ticketOp != operation {
		t.Fatalf("ticket operation = %q, want the supplied %q", record.ticketOp, operation)
	}
	if record.selector != `{"path":"inbox/note.txt"}` {
		t.Fatalf("selector = %s", record.selector)
	}
	if !response.OK || !paths.SafeUploadPath(response.Path) {
		t.Fatalf("response = %+v", response)
	}
}

func TestUploadOperationRefusesAnIdentityItCannotRecover(t *testing.T) {
	record := &accessUploadServer{body: `{"status":"applied"}`}
	api := newAccessUploadServer(t, record)
	if _, err := api.UploadOperation(context.Background(), daemonUUID, "not-a-uuid", DefaultWorkspacePaths(), "note.txt", uploadTempFile(t, "x")); errs.ExitCode(err) != 2 {
		t.Fatalf("UploadOperation() = %v", err)
	}
}

// A 409 from the guest means the workspace moved on. It must not read as a
// denial, and it must never trigger a replay.
func TestRelayConflictSurfacesADistinctRevisionConflict(t *testing.T) {
	record := &accessUploadServer{status: http.StatusConflict}
	api := newAccessUploadServer(t, record)
	_, err := api.UploadOperation(context.Background(), daemonUUID, NewUploadOperationID(), DefaultWorkspacePaths(), "note.txt", uploadTempFile(t, "x"))
	if errs.Code(err) != "revision_conflict" || errs.ExitCode(err) != ExitRevisionConflict {
		t.Fatalf("error = %v (code %s, exit %d)", err, errs.Code(err), errs.ExitCode(err))
	}
}
