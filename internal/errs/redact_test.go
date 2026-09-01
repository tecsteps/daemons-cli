package errs

import "testing"

func TestRedactCoversEveryCredentialShape(t *testing.T) {
	for _, value := range []string{
		"Bearer dr_cp_abc.def-ghi",
		"dr_agent_token",
		"dr_terminal_token",
		"dr_ticket_token",
		"Sec-WebSocket-Protocol: dr.dr_ticket_token",
	} {
		if got := Redact("before " + value + " after"); got != "before [REDACTED] after" && got != "before Sec-WebSocket-Protocol: dr.[REDACTED] after" {
			t.Fatalf("Redact(%q) = %q", value, got)
		}
	}
	if got := Redact("drive_cp_x and dr_other_y"); got != "drive_cp_x and dr_other_y" {
		t.Fatalf("Redact over-matched: %q", got)
	}
}
