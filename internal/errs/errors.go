package errs

import (
	"encoding/json"
	"errors"
	"fmt"
)

type Class string

const (
	ClassFailure      Class = "failure"
	ClassUsage        Class = "usage"
	ClassAuth         Class = "authentication"
	ClassNotFound     Class = "not_found"
	ClassDenied       Class = "denied"
	ClassConfirmation Class = "confirmation_required"
	ClassRateQuota    Class = "rate_or_quota"
	ClassUnknown      Class = "outcome_unknown"
)

type CLIError struct {
	Code           string
	Message        string
	Class          Class
	ExitCode       int
	RequestID      string
	RetryAfter     string
	OperationState string
}

func (e *CLIError) Error() string {
	return e.Message
}

func New(code, message string, exitCode int) error {
	return &CLIError{Code: code, Message: message, Class: classForExitCode(exitCode), ExitCode: exitCode}
}

func NewOperation(code, message, state string, exitCode int) error {
	return &CLIError{
		Code:           code,
		Message:        message,
		Class:          classForExitCode(exitCode),
		ExitCode:       exitCode,
		OperationState: state,
	}
}

type APIError struct {
	Status         int                 `json:"status"`
	Code           string              `json:"code"`
	Detail         string              `json:"detail"`
	Message        string              `json:"message"`
	Errors         map[string][]string `json:"errors"`
	Meta           map[string]any      `json:"meta"`
	RequestID      string              `json:"request_id"`
	RetryAfter     string              `json:"-"`
	Class          Class               `json:"-"`
	OperationState string              `json:"-"`
	Raw            json.RawMessage     `json:"-"`
}

func (e *APIError) Error() string {
	if e.Detail != "" {
		return e.Detail
	}
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("The Control Plane API returned HTTP %d.", e.Status)
}

func ExitCode(err error) int {
	if err == nil {
		return 0
	}

	var cliError *CLIError
	if errors.As(err, &cliError) {
		if cliError.ExitCode != 0 {
			return cliError.ExitCode
		}
		return exitCodeForClass(cliError.Class)
	}

	var apiError *APIError
	if !errors.As(err, &apiError) {
		return 1
	}

	if apiError.Class == "" {
		apiError.Class = classifyAPIError(apiError)
	}
	return exitCodeForClass(apiError.Class)
}

func Code(err error) string {
	var cliError *CLIError
	if errors.As(err, &cliError) {
		return cliError.Code
	}

	var apiError *APIError
	if errors.As(err, &apiError) && apiError.Code != "" {
		return apiError.Code
	}

	return "cli_error"
}

func RawProblem(err error) json.RawMessage {
	var apiError *APIError
	if errors.As(err, &apiError) {
		return apiError.Raw
	}

	return nil
}

func classifyAPIError(apiError *APIError) Class {
	switch {
	case apiError.Status == 401,
		apiError.Code == "authentication_failed",
		apiError.Code == "authentication_required",
		apiError.Code == "token_expired",
		apiError.Code == "ticket_expired":
		return ClassAuth
	case apiError.Status == 404 || apiError.Code == "not_found":
		return ClassNotFound
	case apiError.Status == 403,
		apiError.Code == "scope_denied",
		apiError.Code == "restriction_denied",
		apiError.Code == "capability_denied":
		return ClassDenied
	case apiError.Code == "confirmation_required":
		return ClassConfirmation
	case apiError.Status == 413,
		apiError.Status == 429,
		apiError.Status == 507,
		apiError.Code == "file_too_large",
		apiError.Code == "daemon_storage_full",
		apiError.Code == "rate_limited",
		apiError.Code == "quota_exceeded",
		apiError.Code == "capacity_exceeded",
		apiError.Code == "insufficient_capacity":
		return ClassRateQuota
	case apiError.Status == 504 || apiError.Code == "outcome_unknown":
		return ClassUnknown
	default:
		return ClassFailure
	}
}

func classForExitCode(exitCode int) Class {
	switch exitCode {
	case 2:
		return ClassUsage
	case 3:
		return ClassAuth
	case 4:
		return ClassNotFound
	case 5:
		return ClassDenied
	case 6:
		return ClassConfirmation
	case 7:
		return ClassRateQuota
	case 8:
		return ClassUnknown
	default:
		return ClassFailure
	}
}

func exitCodeForClass(class Class) int {
	switch class {
	case ClassUsage:
		return 2
	case ClassAuth:
		return 3
	case ClassNotFound:
		return 4
	case ClassDenied:
		return 5
	case ClassConfirmation:
		return 6
	case ClassRateQuota:
		return 7
	case ClassUnknown:
		return 8
	default:
		return 1
	}
}
