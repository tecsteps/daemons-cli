package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

// lockChallengeServer answers the ticket request, then sends one
// lock_device_challenge and reports whatever the client sends back.
func lockChallengeServer(t *testing.T, replies chan<- string) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1":
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
		case "/api/v1/daemons/daemon-uuid/terminal-tickets":
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			json.NewEncoder(writer).Encode(map[string]any{
				"data": map[string]any{
					"gateway_url":       "ws" + strings.TrimPrefix(server.URL, "http") + "/term",
					"ticket":            "fake.ticket",
					"expires_in":        "30.00",
					"terminal_protocol": "1",
					"features":          []string{"takeover_v1"},
				},
				"meta": []any{},
			})
		case "/term":
			connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
				Subprotocols:       []string{"dr.fake.ticket"},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Errorf("Accept() error = %v", err)
				return
			}
			defer connection.CloseNow()
			challenge := `{"type":"lock_device_challenge","frame":"{\"challenge_uuid\":\"synthetic\"}"}`
			if err := connection.Write(request.Context(), websocket.MessageText, []byte(challenge)); err != nil {
				return
			}
			_, payload, err := connection.Read(request.Context())
			if err != nil {
				replies <- ""
				return
			}
			replies <- string(payload)
			connection.Close(websocket.StatusNormalClosure, "proof_accepted")
		}
	}))
	return server
}

func TestAttachAnswersALockDeviceChallengeWithTheStoredGrant(t *testing.T) {
	replies := make(chan string, 1)
	server := lockChallengeServer(t, replies)
	defer server.Close()
	api, err := client.New(server.URL, "dr_cp_test", client.WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	seen := make(chan string, 1)
	outcomes := make(chan Outcome, 1)
	go func() {
		outcome, _ := Connect(context.Background(), api, "daemon-uuid", "main", Size{Cols: 80, Rows: 24}, Streams{
			Input:  reader,
			Output: io.Discard,
			Resize: make(chan Size),
			Lock: func(envelope string) (string, error) {
				seen <- envelope
				return `{"type":"lock_device_proof","proof":{"device_session_uuid":"synthetic"}}`, nil
			},
		})
		outcomes <- outcome
	}()
	select {
	case envelope := <-seen:
		if !strings.Contains(envelope, "lock_device_challenge") {
			t.Fatalf("responder saw %q", envelope)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the responder was never called")
	}
	select {
	case reply := <-replies:
		if !strings.Contains(reply, "lock_device_proof") {
			t.Fatalf("gateway received %q", reply)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("no proof reached the gateway")
	}
	writer.Close()
	select {
	case <-outcomes:
	case <-time.After(3 * time.Second):
		t.Fatal("attach did not finish after the gateway closed")
	}
}

func TestAttachRefusesAProtectedWorkspaceWithoutAGrant(t *testing.T) {
	replies := make(chan string, 1)
	server := lockChallengeServer(t, replies)
	defer server.Close()
	api, err := client.New(server.URL, "dr_cp_test", client.WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	outcome, err := Connect(context.Background(), api, "daemon-uuid", "main", Size{Cols: 80, Rows: 24}, Streams{
		Input:  reader,
		Output: io.Discard,
		Resize: make(chan Size),
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if outcome.ExitCode != 5 || outcome.LockError == nil {
		t.Fatalf("outcome = %#v", outcome)
	}
	if errs.Code(outcome.LockError) != "lock_device_required" {
		t.Fatalf("lock error = %v", outcome.LockError)
	}
}

func TestAttachSurfacesAResponderFailureWithoutSendingAProof(t *testing.T) {
	replies := make(chan string, 1)
	server := lockChallengeServer(t, replies)
	defer server.Close()
	api, err := client.New(server.URL, "dr_cp_test", client.WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	reader, writer := io.Pipe()
	defer reader.Close()
	defer writer.Close()
	expired := errs.New("lock_session_expired", "The device session expired. Unlock again.", 5)
	outcome, err := Connect(context.Background(), api, "daemon-uuid", "main", Size{Cols: 80, Rows: 24}, Streams{
		Input:  reader,
		Output: io.Discard,
		Resize: make(chan Size),
		Lock:   func(string) (string, error) { return "", expired },
	})
	if err != nil {
		t.Fatalf("Connect() error = %v", err)
	}
	if outcome.ExitCode != 5 || !errors.Is(outcome.LockError, expired) {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestOnlyALockDeviceChallengeReachesTheResponder(t *testing.T) {
	for _, payload := range []string{`{"type":"session_required"}`, `not json`, ``, `{"type":"lock_device_proof"}`} {
		if isLockDeviceChallenge([]byte(payload)) {
			t.Fatalf("%q was treated as a challenge", payload)
		}
	}
	if !isLockDeviceChallenge([]byte(`{"type":"lock_device_challenge","frame":"{}"}`)) {
		t.Fatal("a real challenge was not recognised")
	}
	oversized := make([]byte, client.LockEnvelopeLimit+1)
	if isLockDeviceChallenge(oversized) {
		t.Fatal("an oversized envelope was accepted")
	}
}
