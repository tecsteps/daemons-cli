package client

import (
	"errors"
	"net/http"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

// TestAdmittedLockActionsKeepTheirOwnDenial proves the CLI distinguishes an
// action this platform never carries from one it carries and refused.
func TestAdmittedLockActionsKeepTheirOwnDenial(t *testing.T) {
	denied := &errs.APIError{Status: http.StatusUnprocessableEntity, Code: "forbidden"}
	for _, action := range AdmittedLockActions {
		if got := lockAdmissionError(action, denied); !errors.Is(got, denied) {
			t.Fatalf("%s admission error = %v, want the Control Plane's own error", action, got)
		}
	}
	for _, action := range []string{"lock.lock", "lock.status", "lock.setup", "lock.organization.disable"} {
		got := lockAdmissionError(action, denied)
		if errs.Code(got) != "lock_protocol_unsupported" {
			t.Fatalf("%s admission error = %v, want lock_protocol_unsupported", action, got)
		}
	}
	// A transport failure is never turned into a version gap.
	transport := errors.New("connection reset")
	if got := lockAdmissionError("lock.lock", transport); !errors.Is(got, transport) {
		t.Fatalf("transport error = %v, want the original", got)
	}
}
