package errs

import "testing"

func TestExitCodeTaxonomy(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "success", err: nil, want: 0},
		{name: "failure", err: New("failure", "failed", 1), want: 1},
		{name: "usage", err: New("usage_error", "invalid", 2), want: 2},
		{name: "authentication", err: &APIError{Status: 401, Code: "authentication_failed"}, want: 3},
		{name: "not found", err: &APIError{Status: 404, Code: "not_found"}, want: 4},
		{name: "denied", err: &APIError{Status: 403, Code: "scope_denied"}, want: 5},
		{name: "confirmation", err: &APIError{Status: 409, Code: "confirmation_required"}, want: 6},
		{name: "rate or quota", err: &APIError{Status: 429, Code: "rate_limited"}, want: 7},
		{name: "outcome unknown code", err: &APIError{Status: 500, Code: "outcome_unknown"}, want: 8},
		{name: "gateway timeout outcome unknown", err: &APIError{Status: 504}, want: 8},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := ExitCode(test.err); got != test.want {
				t.Fatalf("ExitCode() = %d, want %d", got, test.want)
			}
		})
	}
}

func TestAttachSpecificExitCodesRemainNamespaced(t *testing.T) {
	for _, exitCode := range []int{9, 10, 11, 42} {
		if got := ExitCode(New("terminal_outcome", "closed", exitCode)); got != exitCode {
			t.Fatalf("ExitCode() = %d, want %d", got, exitCode)
		}
	}
}

func TestOperationErrorRetainsStateAndClass(t *testing.T) {
	err := NewOperation("operation_failed", "failed", "partially_succeeded", 1)
	cliError, ok := err.(*CLIError)
	if !ok {
		t.Fatalf("error type = %T", err)
	}
	if cliError.OperationState != "partially_succeeded" || cliError.Class != ClassFailure {
		t.Fatalf("CLIError = %#v", cliError)
	}
}
