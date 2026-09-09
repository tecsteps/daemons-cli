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

// TestDecisionResultsNeverReportADenialAsSuccess is the review's high finding:
// a sealed refusal must fail the command, not print "approved".
func TestDecisionResultsNeverReportADenialAsSuccess(t *testing.T) {
	applied := map[string]any{"action": "lock.handoff", "operation_uuid": "op", "outcome": "applied"}
	if err := ReadLockDecisionResult(applied, "lock.handoff"); err != nil {
		t.Fatalf("an applied decision failed: %v", err)
	}
	denied := map[string]any{"action": "lock.handoff", "operation_uuid": "op",
		"outcome": "denied", "reason": "lock_denied"}
	err := ReadLockDecisionResult(denied, "lock.handoff")
	if err == nil {
		t.Fatal("a sealed denial was reported as success")
	}
	if errs.ExitCode(err) == 0 {
		t.Fatalf("a denial exited zero: %v", err)
	}
	if errs.Code(err) != "lock_attempt_failed" {
		t.Fatalf("denial mapped to %q", errs.Code(err))
	}

	// A rotation may legitimately stage; a handoff may not.
	pending := map[string]any{"action": "lock.organization.rotate", "operation_uuid": "op", "outcome": "pending"}
	if err := ReadLockDecisionResult(pending, "lock.organization.rotate"); err != nil {
		t.Fatalf("a staged rotation failed: %v", err)
	}
	if err := ReadLockDecisionResult(map[string]any{"action": "lock.handoff",
		"operation_uuid": "op", "outcome": "pending"}, "lock.handoff"); err == nil {
		t.Fatal("a pending handoff was reported as success")
	}

	// An outcome the guest never names, or a denial with extra fields, is still a refusal.
	for _, result := range []map[string]any{
		{"action": "lock.handoff", "operation_uuid": "op", "outcome": "confirmed"},
		{"action": "lock.handoff", "operation_uuid": "op"},
		{"action": "lock.handoff", "operation_uuid": "op", "outcome": "denied"},
		{"action": "lock.handoff", "operation_uuid": "op", "outcome": "denied",
			"reason": "lock_denied", "extra": true},
	} {
		if err := ReadLockDecisionResult(result, "lock.handoff"); err == nil {
			t.Fatalf("%v was reported as success", result)
		}
	}
}

// TestPushConfirmationIsNotOnTheCliSurface keeps E23's frame off this client.
func TestPushConfirmationIsNotOnTheCliSurface(t *testing.T) {
	for _, action := range AdmittedLockActions {
		if action == "lock.push_confirmation" {
			t.Fatal("the CLI admits E23's push confirmation")
		}
	}
	if errs.Code(lockAdmissionError("lock.push_confirmation",
		&errs.APIError{Status: http.StatusUnprocessableEntity, Code: "forbidden"})) != "lock_protocol_unsupported" {
		t.Fatal("push confirmation is not reported as unavailable from the CLI")
	}
}
