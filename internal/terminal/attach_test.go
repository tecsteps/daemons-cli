package terminal

import (
	"errors"
	"strings"
	"testing"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/errs"
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

func TestCheckFeaturesRequiresAdvertisedTakeover(t *testing.T) {
	if err := CheckFeatures([]string{"takeover_v1", "future_feature"}); err != nil {
		t.Fatalf("advertised features refused: %v", err)
	}
	for _, advertised := range [][]string{nil, {}, {"reattach_only_v1"}} {
		err := CheckFeatures(advertised)
		if err == nil || errs.ExitCode(err) != 2 || errs.Code(err) != "terminal_feature_unavailable" {
			t.Fatalf("CheckFeatures(%v) = %v", advertised, err)
		}
	}
}

func TestDialErrorSummaryNeverCarriesTheTicket(t *testing.T) {
	err := errors.New("failed to WebSocket dial: Sec-WebSocket-Protocol dr.dr_ticket_secret rejected")
	summary := errs.Redact(summarizeDialError(err))
	if strings.Contains(summary, "secret") {
		t.Fatalf("summary = %q", summary)
	}
}
