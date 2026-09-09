package app

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

type blockingSSHInput struct {
	release chan struct{}
	once    sync.Once
}

func (input *blockingSSHInput) Read(_ []byte) (int, error) {
	<-input.release
	return 0, context.Canceled
}

func (input *blockingSSHInput) Close() error {
	input.once.Do(func() { close(input.release) })
	return nil
}

type closingSSHOutput struct {
	bytes.Buffer
	mu     sync.Mutex
	closed bool
}

func (output *closingSSHOutput) Close() error {
	output.mu.Lock()
	defer output.mu.Unlock()
	output.closed = true
	return nil
}

func (output *closingSSHOutput) isClosed() bool {
	output.mu.Lock()
	defer output.mu.Unlock()
	return output.closed
}

func TestSSHProxyControlFramesAreStable(t *testing.T) {
	if sshControlReady != `{"type":"ready"}` || sshControlEOF != `{"type":"eof"}` {
		t.Fatalf("unexpected SSH control frames: %q %q", sshControlReady, sshControlEOF)
	}
}

func TestRelaySSHExitsAndClosesStdoutWhenGatewayCloses(t *testing.T) {
	input := &blockingSSHInput{release: make(chan struct{})}
	output := &closingSSHOutput{}
	payload := bytes.Repeat([]byte("x"), 64*1024)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		if err := connection.Write(r.Context(), websocket.MessageText, []byte(sshControlReady)); err != nil {
			t.Errorf("write ready: %v", err)
			return
		}
		if err := connection.Write(r.Context(), websocket.MessageBinary, payload); err != nil {
			t.Errorf("write binary payload: %v", err)
			return
		}
		_ = connection.Close(websocket.StatusTryAgainLater, "output_backpressure")
	}))
	defer server.Close()

	done := make(chan error, 1)
	go func() {
		done <- relaySSH(
			context.Background(),
			"ws"+strings.TrimPrefix(server.URL, "http"),
			"ticket",
			Dependencies{Input: input, Output: output, ErrorOutput: &bytes.Buffer{}},
			nil,
			nil,
		)
	}()

	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected the gateway close to fail the relay")
		}
		if !strings.Contains(err.Error(), "1013") {
			t.Fatalf("expected close status in error, got %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not exit within one second")
	}

	if !output.isClosed() {
		t.Fatal("relay stdout was not closed")
	}
	if !bytes.Equal(output.Bytes(), payload) {
		t.Fatalf("relay output length = %d, want %d", output.Len(), len(payload))
	}
}

func TestRelaySSHAnswersALockDeviceChallengeBeforeReady(t *testing.T) {
	proofs := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer connection.CloseNow()
		challenge := `{"type":"lock_device_challenge","frame":"{\"challenge_uuid\":\"synthetic\"}"}`
		if err := connection.Write(r.Context(), websocket.MessageText, []byte(challenge)); err != nil {
			return
		}
		_, payload, err := connection.Read(r.Context())
		if err != nil {
			return
		}
		proofs <- string(payload)
		if err := connection.Write(r.Context(), websocket.MessageText, []byte(sshControlReady)); err != nil {
			return
		}
		_ = connection.Close(websocket.StatusNormalClosure, "")
	}))
	defer server.Close()

	err := relaySSH(
		context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http"),
		"ticket",
		Dependencies{Input: bytes.NewReader(nil), Output: io.Discard, ErrorOutput: &bytes.Buffer{}},
		func(envelope string) (string, error) {
			if !client.IsLockDeviceChallenge([]byte(envelope)) {
				t.Fatalf("responder saw %q", envelope)
			}
			return `{"type":"lock_device_proof","proof":{"device_session_uuid":"synthetic","challenge_uuid":"synthetic","signature":"c2ln"}}`, nil
		},
		nil,
	)
	if err != nil {
		t.Fatalf("relaySSH() error = %v", err)
	}
	select {
	case proof := <-proofs:
		if !strings.Contains(proof, "lock_device_proof") {
			t.Fatalf("gateway received %q", proof)
		}
	default:
		t.Fatal("no proof reached the gateway")
	}
}

func TestRelaySSHRefusesAProtectedWorkspaceWithoutAGrant(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer connection.CloseNow()
		_ = connection.Write(r.Context(), websocket.MessageText, []byte(`{"type":"lock_device_challenge","frame":"{}"}`))
		_, _, _ = connection.Read(r.Context())
	}))
	defer server.Close()

	err := relaySSH(
		context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http"),
		"ticket",
		Dependencies{Input: bytes.NewReader(nil), Output: io.Discard, ErrorOutput: &bytes.Buffer{}},
		nil,
		nil,
	)
	if errs.Code(err) != "lock_device_required" || errs.ExitCode(err) != 5 {
		t.Fatalf("error = %v", err)
	}
}

func TestRelaySSHSurfacesAStaleGrantWithoutSendingAProof(t *testing.T) {
	proofs := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		connection, err := websocket.Accept(w, r, nil)
		if err != nil {
			t.Errorf("accept websocket: %v", err)
			return
		}
		defer connection.CloseNow()
		_ = connection.Write(r.Context(), websocket.MessageText, []byte(`{"type":"lock_device_challenge","frame":"{}"}`))
		_, payload, err := connection.Read(r.Context())
		if err == nil {
			proofs <- string(payload)
		}
	}))
	defer server.Close()

	expired := errs.New("lock_session_expired", "The device session expired. Unlock again.", 5)
	err := relaySSH(
		context.Background(),
		"ws"+strings.TrimPrefix(server.URL, "http"),
		"ticket",
		Dependencies{Input: bytes.NewReader(nil), Output: io.Discard, ErrorOutput: &bytes.Buffer{}},
		func(string) (string, error) { return "", expired },
		nil,
	)
	if !errors.Is(err, expired) {
		t.Fatalf("error = %v", err)
	}
	select {
	case proof := <-proofs:
		t.Fatalf("stale grant still sent %q", proof)
	default:
	}
}
