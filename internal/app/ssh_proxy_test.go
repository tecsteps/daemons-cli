package app

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
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
