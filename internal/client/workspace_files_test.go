package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const filesTestWorkspace = "11111111-1111-4111-8111-111111111111"

type filesChannelMode string

const (
	filesProofSent filesChannelMode = "proof"
	filesMissing   filesChannelMode = "missing"
	filesStale     filesChannelMode = "stale"
)

type filesChannelFake struct {
	mu       sync.Mutex
	proofs   []string
	requests []string
}

func (f *filesChannelFake) addProof(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.proofs = append(f.proofs, value)
}

func (f *filesChannelFake) addRequest(value string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, value)
}

func filesTicketPath(action string) (method, suffix string) {
	switch action {
	case "files.upload":
		return http.MethodPut, "/files/uploads/"
	case "files.download":
		return http.MethodPost, "/files/downloads"
	default:
		return http.MethodPost, "/files/query"
	}
}

func filesChannelServer(t *testing.T, action string, fake *filesChannelFake) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch {
		case request.URL.Path == "/api/v1":
			io.WriteString(writer, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case request.URL.Path == "/api/v1/daemons/"+filesTestWorkspace+"/access-tickets":
			var metadata map[string]string
			if err := json.NewDecoder(request.Body).Decode(&metadata); err != nil {
				t.Error(err)
				return
			}
			if metadata["action"] != action || metadata["operation_uuid"] == "" {
				t.Errorf("unexpected ticket metadata %v", metadata)
			}
			method, suffix := filesTicketPath(action)
			if action == "files.upload" {
				suffix += metadata["operation_uuid"]
			}
			json.NewEncoder(writer).Encode(map[string]any{
				"data": map[string]any{
					"ticket":             "opaque.ticket",
					"ticket_version":     2,
					"expires_in":         30,
					"method":             method,
					"gateway_path":       "/v1/workspaces/" + filesTestWorkspace + suffix,
					"websocket_protocol": FilesProtocolLabel,
				},
			})
		case request.URL.Path == "/v1/workspaces/"+filesTestWorkspace+"/files/channel":
			connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
				Subprotocols:       []string{FilesProtocolLabel, "dr.opaque.ticket"},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Errorf("Accept() error = %v", err)
				return
			}
			defer connection.CloseNow()
			ctx := request.Context()
			challenge := `{"type":"lock_device_challenge","frame":"{\"challenge_uuid\":\"synthetic\"}"}`
			if err := connection.Write(ctx, websocket.MessageText, []byte(challenge)); err != nil {
				return
			}
			kind, payload, err := connection.Read(ctx)
			if err != nil || kind != websocket.MessageText {
				return
			}
			fake.addProof(string(payload))
			if !strings.Contains(string(payload), "lock_device_proof") {
				return
			}
			if err := connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_ready"}`)); err != nil {
				return
			}
			kind, payload, err = connection.Read(ctx)
			if err != nil || kind != websocket.MessageText {
				return
			}
			fake.addRequest(string(payload))
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
						Type     string `json:"type"`
						Sequence int    `json:"sequence"`
					}
					if json.Unmarshal(payload, &frame) != nil {
						return
					}
					if frame.Type == "file_upload_complete" {
						_ = connection.Write(ctx, websocket.MessageText, []byte(`{"type":"file_result","data":{"status":"applied","bytes":5,"path":"/workspace/note.txt"}}`))
						return
					}
					pull, err := json.Marshal(map[string]any{"type": "file_upload_pull", "sequence": frame.Sequence + 1})
					if err != nil {
						return
					}
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
	t.Cleanup(server.Close)
	return server
}

func filesSource(t *testing.T, action string) io.Reader {
	t.Helper()
	switch action {
	case "files.upload":
		selector, err := json.Marshal(map[string]string{"path": "note.txt"})
		if err != nil {
			t.Fatal(err)
		}
		prelude := make([]byte, 4+len(selector))
		binary.BigEndian.PutUint32(prelude, uint32(len(selector)))
		copy(prelude[4:], selector)
		return io.MultiReader(bytes.NewReader(prelude), bytes.NewReader([]byte("hello")))
	case "files.download":
		return bytes.NewReader([]byte(`{"path":"note.txt"}`))
	default:
		return bytes.NewReader([]byte(`{"path":"","cursor":"","limit":20}`))
	}
}

func TestAccessContentFilesChannelAnswersADeviceChallenge(t *testing.T) {
	for _, action := range []string{"files.read", "files.upload", "files.download"} {
		for _, mode := range []filesChannelMode{filesProofSent, filesMissing, filesStale} {
			t.Run(action+"/"+string(mode), func(t *testing.T) {
				fake := &filesChannelFake{}
				server := filesChannelServer(t, action, fake)
				api, err := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()), WithVersion("test"))
				if err != nil {
					t.Fatal(err)
				}
				switch mode {
				case filesProofSent:
					api.SetWorkingProof(func(got string) (func(string) (string, error), error) {
						if got != action {
							t.Fatalf("prove action = %q", got)
						}
						return func(envelope string) (string, error) {
							if !IsLockDeviceChallenge([]byte(envelope)) {
								t.Fatalf("responder saw %q", envelope)
							}
							return `{"type":"lock_device_proof","proof":{"device_session_uuid":"synthetic","challenge_uuid":"synthetic","signature":"c2ln"}}`, nil
						}, nil
					})
				case filesStale:
					expired := errs.New("lock_session_expired", "The device session expired. Unlock again.", 5)
					api.SetWorkingProof(func(string) (func(string) (string, error), error) {
						return func(string) (string, error) { return "", expired }, nil
					})
				}
				var dest bytes.Buffer
				err = api.AccessContent(context.Background(), filesTestWorkspace, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", action, filesSource(t, action), &dest)
				switch mode {
				case filesProofSent:
					if err != nil {
						t.Fatalf("AccessContent() error = %v", err)
					}
					if len(fake.proofs) != 1 || !strings.Contains(fake.proofs[0], "lock_device_proof") {
						t.Fatalf("proofs = %v", fake.proofs)
					}
					if !strings.Contains(fake.proofs[0], "device_session_uuid") {
						t.Fatal("proof envelope was empty")
					}
					if len(fake.requests) != 1 || !strings.Contains(fake.requests[0], "file_request") {
						t.Fatalf("requests = %v", fake.requests)
					}
					if action == "files.download" {
						if dest.String() != "abc" {
							t.Fatalf("download dest = %q", dest.String())
						}
					} else if !bytes.Contains(dest.Bytes(), []byte(`"data"`)) && !bytes.Contains(dest.Bytes(), []byte(`"status"`)) {
						t.Fatalf("result dest = %q", dest.String())
					}
				case filesMissing:
					if errs.Code(err) != "lock_device_required" || errs.ExitCode(err) != 5 {
						t.Fatalf("error = %v", err)
					}
					if len(fake.proofs) != 0 {
						t.Fatalf("missing grant still sent %v", fake.proofs)
					}
				case filesStale:
					if errs.Code(err) != "lock_session_expired" || errs.ExitCode(err) != 5 {
						t.Fatalf("error = %v", err)
					}
					if len(fake.proofs) != 0 {
						t.Fatalf("stale grant still sent %v", fake.proofs)
					}
				}
			})
		}
	}
}

func TestAccessContentKeepsHTTPWhenTheFilesProtocolIsAbsent(t *testing.T) {
	relays := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch r.URL.Path {
		case "/api/v1":
			io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case "/api/v1/daemons/" + filesTestWorkspace + "/access-tickets":
			io.WriteString(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"POST","gateway_path":"/v1/workspaces/`+filesTestWorkspace+`/files/query"}}`)
		case "/v1/workspaces/" + filesTestWorkspace + "/files/query":
			relays++
			io.WriteString(w, `{"data":[],"meta":{"next_cursor":null}}`)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	t.Cleanup(server.Close)
	api, err := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()), WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	var dest bytes.Buffer
	if err := api.AccessContent(context.Background(), filesTestWorkspace, "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", "files.read", bytes.NewReader([]byte(`{"path":""}`)), &dest); err != nil {
		t.Fatal(err)
	}
	if relays != 1 {
		t.Fatalf("relays = %d", relays)
	}
}

func TestIsLockDeviceChallengeRejectsForeignFrames(t *testing.T) {
	if IsLockDeviceChallenge([]byte(`{"type":"file_ready"}`)) {
		t.Fatal("file_ready was treated as a challenge")
	}
}
