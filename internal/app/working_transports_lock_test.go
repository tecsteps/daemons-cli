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
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/credentials"
)

type workingProofMode string

const (
	workingProofSent workingProofMode = "proof"
	workingMissing   workingProofMode = "missing"
	workingStale     workingProofMode = "stale"
)

type workingTransportFake struct {
	mu     sync.Mutex
	proofs []string
}

func (f *workingTransportFake) add(proof string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proofs = append(f.proofs, proof)
}

func installWorkingGrant(t *testing.T, storePath, baseURL string, guest *lockGuest, nowMs int64) {
	t.Helper()
	device, err := client.NewLockDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	store := credentials.LockStore{Path: storePath}
	scope := credentials.LockScope{
		BaseURL:              baseURL,
		OrganizationUUID:     lockTestOrgUUID,
		WorkspaceUUID:        lockTestWorkspace,
		AssignmentGeneration: guest.generation,
	}
	if err := store.Pin(scope, guest.identityPin(), credentials.LockPinManualComparison); err != nil {
		t.Fatal(err)
	}
	grant := credentials.LockGrant{
		DeviceSessionUUID:  lockTestSession,
		DeviceScalar:       device.Scalar(),
		ExpiresAtMs:        nowMs + credentials.LockGrantLifetimeMs,
		BootUUID:           lockTestBootUUID,
		LockEpoch:          1,
		CredentialRevision: 1,
		ActorSubjectUUID:   lockTestSubject,
		MembershipUUID:     lockTestMembership,
	}
	if err := store.Grant(scope, guest.identityPin(), grant, nowMs); err != nil {
		t.Fatal(err)
	}
}

func workingFilesServer(t *testing.T, guest *lockGuest, fake *workingTransportFake, epoch int64) *httptest.Server {
	t.Helper()
	var current struct {
		sync.Mutex
		action string
	}
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch {
		case request.URL.Path == "/api/v1":
			io.WriteString(writer, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case request.URL.Path == "/api/v1/daemons" || request.URL.Path == "/api/v1/daemons/"+lockTestWorkspace:
			fmt.Fprintf(writer, `{"data":[{"id":%q,"name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"}}],"meta":{}}`, lockTestWorkspace)
		case request.URL.Path == "/api/v1/daemons/"+lockTestWorkspace+"/access-tickets":
			var metadata map[string]string
			if err := json.NewDecoder(request.Body).Decode(&metadata); err != nil {
				t.Error(err)
				return
			}
			action := metadata["action"]
			current.Lock()
			current.action = action
			current.Unlock()
			method, suffix := "POST", "/files/query"
			switch action {
			case "files.upload":
				method, suffix = "PUT", "/files/uploads/"+metadata["operation_uuid"]
			case "files.download":
				suffix = "/files/downloads"
			}
			fmt.Fprintf(writer, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":%q,"gateway_path":"/v1/workspaces/%s%s","websocket_protocol":%q}}`, method, lockTestWorkspace, suffix, client.FilesProtocolLabel)
		case request.URL.Path == "/v1/workspaces/"+lockTestWorkspace+"/files/channel":
			connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
				Subprotocols:       []string{client.FilesProtocolLabel, "dr.opaque.ticket"},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Errorf("Accept() error = %v", err)
				return
			}
			defer connection.CloseNow()
			ctx := request.Context()
			current.Lock()
			action := current.action
			current.Unlock()
			if err := connection.Write(ctx, websocket.MessageText, []byte(guest.workingChallengeEnvelope(t, action, lockTestWorkspace, epoch))); err != nil {
				return
			}
			kind, payload, err := connection.Read(ctx)
			if err != nil || kind != websocket.MessageText {
				return
			}
			fake.add(string(payload))
			if !strings.Contains(string(payload), "lock_device_proof") {
				return
			}
			if err := connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_ready"}`)); err != nil {
				return
			}
			if _, _, err := connection.Read(ctx); err != nil {
				return
			}
			switch action {
			case "files.download":
				if err := connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_chunk","sequence":0,"chunk":"YWJj"}`)); err != nil {
					return
				}
				if _, _, err := connection.Read(ctx); err != nil {
					return
				}
				_ = connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_result","data":{"bytes":3}}`))
			case "files.upload":
				if err := connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_upload_pull","sequence":0}`)); err != nil {
					return
				}
				for {
					kind, payload, err = connection.Read(ctx)
					if err != nil || kind != websocket.MessageText {
						return
					}
					var frame struct {
						Type string `json:"type"`
					}
					if json.Unmarshal(payload, &frame) != nil {
						return
					}
					if frame.Type == "file_upload_complete" {
						_ = connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_result","data":{"status":"applied","bytes":5,"path":"/home/dr-agent/workspace/uploads/note.txt","sha256":"`+strings.Repeat("a", 64)+`"}}`))
						return
					}
					pull, _ := json.Marshal(map[string]any{"type": "file_upload_pull", "sequence": 1})
					if err := connection.Write(ctx, websocket.MessageText, pull); err != nil {
						return
					}
				}
			default:
				_ = connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_result","data":{"data":[{"name":"note.txt","type":"file","size":5,"mtime":1}],"meta":{"next_cursor":null}}}`))
			}
		default:
			t.Errorf("unexpected endpoint %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	}))
}

func workingSSHServer(t *testing.T, guest *lockGuest, fake *workingTransportFake, epoch int64) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch request.URL.Path {
		case "/api/v1":
			io.WriteString(writer, `{"data":{"version":"v1"}}`)
		case "/api/v1/daemons/" + lockTestWorkspace + "/ssh/ticket":
			fmt.Fprintf(writer, `{"data":{"ticket":"opaque.ticket","expires_in":30,"gateway_url":%q}}`, "ws"+strings.TrimPrefix(server.URL, "http")+"/ssh")
		case "/ssh":
			connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{InsecureSkipVerify: true})
			if err != nil {
				t.Errorf("accept websocket: %v", err)
				return
			}
			defer connection.CloseNow()
			ctx := request.Context()
			if err := connection.Write(ctx, websocket.MessageText, []byte(guest.workingChallengeEnvelope(t, "ssh.connect", lockTestWorkspace, epoch))); err != nil {
				return
			}
			kind, payload, err := connection.Read(ctx)
			if err != nil || kind != websocket.MessageText {
				return
			}
			fake.add(string(payload))
			if !strings.Contains(string(payload), "lock_device_proof") {
				return
			}
			if err := connection.Write(ctx, websocket.MessageText, []byte(sshControlReady)); err != nil {
				return
			}
			_ = connection.Close(websocket.StatusNormalClosure, "")
		default:
			t.Errorf("unexpected endpoint %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	return server
}

func TestWorkingTransportCommandsProveTheDeviceGrant(t *testing.T) {
	const nowMs int64 = 1_700_000_000_000
	localFile := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(localFile, []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	commands := []struct {
		name  string
		files bool
		args  func(dest string) []string
	}{
		{name: "files list", files: true, args: func(string) []string {
			return []string{"--json", "files", "list", lockTestWorkspace}
		}},
		{name: "files download", files: true, args: func(dest string) []string {
			return []string{"--json", "files", "download", lockTestWorkspace, "note.txt", dest}
		}},
		{name: "upload", files: true, args: func(string) []string {
			return []string{"--json", "upload", lockTestWorkspace, localFile, "--force"}
		}},
		{name: "ssh-proxy", files: false, args: func(string) []string {
			return []string{"--json", "ssh-proxy", lockTestWorkspace}
		}},
	}

	for _, command := range commands {
		for _, mode := range []workingProofMode{workingProofSent, workingMissing, workingStale} {
			t.Run(command.name+"/"+string(mode), func(t *testing.T) {
				guest := newLockGuest(t, nowMs)
				fake := &workingTransportFake{}
				epoch := int64(1)
				if mode == workingStale {
					epoch = 2
				}
				var server *httptest.Server
				if command.files {
					server = workingFilesServer(t, guest, fake, epoch)
					t.Cleanup(server.Close)
				} else {
					server = workingSSHServer(t, guest, fake, epoch)
				}
				var output, errorOutput bytes.Buffer
				deps := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
				deps.Input = bytes.NewReader(nil)
				deps.Now = func() time.Time { return time.UnixMilli(nowMs).UTC() }
				storePath := filepath.Join(t.TempDir(), "workspace-lock.json")
				deps.Environment["DAEMONS_WORKSPACE_LOCK_FILE"] = storePath
				if mode != workingMissing {
					baseURL, err := client.NormalizeBaseURL(server.URL)
					if err != nil {
						t.Fatal(err)
					}
					installWorkingGrant(t, storePath, baseURL, guest, nowMs)
				}
				dest := filepath.Join(t.TempDir(), "downloaded.bin")
				args := append([]string{"--host", server.URL}, command.args(dest)...)
				code := Run(context.Background(), args, deps)
				switch mode {
				case workingProofSent:
					if code != 0 {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
					}
					if len(fake.proofs) == 0 || !strings.Contains(fake.proofs[0], "lock_device_proof") {
						t.Fatalf("proofs = %v", fake.proofs)
					}
				case workingMissing:
					if code != 5 || !strings.Contains(output.String()+errorOutput.String(), "lock_device_required") {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
					}
					if len(fake.proofs) != 0 {
						t.Fatalf("missing grant still sent %v", fake.proofs)
					}
				case workingStale:
					if code != 5 || !strings.Contains(output.String()+errorOutput.String(), "lock_session_expired") {
						t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
					}
					if len(fake.proofs) != 0 {
						t.Fatalf("stale grant still sent %v", fake.proofs)
					}
				}
			})
		}
	}
}
