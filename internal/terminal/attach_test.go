package terminal

import (
	"testing"

	"github.com/coder/websocket"
)

func TestLocalPrefixDetachAndLiteralForwarding(t *testing.T) {
	payload, detach, pending := localPrefix([]byte{'a', prefixByte, prefixByte, 'b'}, false)
	if detach || pending || string(payload) != string([]byte{'a', prefixByte, 'b'}) {
		t.Fatalf("localPrefix literal = %q, %v, %v", payload, detach, pending)
	}

	payload, detach, pending = localPrefix([]byte{prefixByte}, false)
	if detach || !pending || len(payload) != 0 {
		t.Fatalf("localPrefix pending = %q, %v, %v", payload, detach, pending)
	}
	payload, detach, pending = localPrefix([]byte{'d'}, pending)
	if !detach || pending || len(payload) != 0 {
		t.Fatalf("localPrefix detach = %q, %v, %v", payload, detach, pending)
	}
}

func TestSocketCloseExitCodes(t *testing.T) {
	tests := map[int]int{1000: 0, 4401: 3, 4403: 5, 4409: 11, 1011: 1}
	for status, want := range tests {
		err := websocket.CloseError{Code: websocket.StatusCode(status)}
		got := outcomeForSocketError(err).ExitCode
		if got != want {
			t.Fatalf("status %d exit = %d, want %d", status, got, want)
		}
	}
}
