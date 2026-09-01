package app

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func writeJSON(writer io.Writer, value any) {
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(false)
	_ = encoder.Encode(value)
}

func writeCanonicalJSON(writer io.Writer, raw json.RawMessage) {
	trimmed := bytes.TrimSpace(raw)
	if len(trimmed) == 0 {
		trimmed = []byte(`{"data":null,"meta":{}}`)
	}
	_, _ = writer.Write(trimmed)
	_, _ = fmt.Fprintln(writer)
}

func writeError(dependencies Dependencies, jsonOutput bool, err error) {
	if jsonOutput {
		if raw := errs.RawProblem(err); len(raw) > 0 {
			if sanitized := sanitizeProblem(raw); len(sanitized) > 0 {
				writeCanonicalJSON(dependencies.Output, sanitized)
				return
			}
		}
		writeJSON(dependencies.Output, canonicalProblem(err))
		return
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Error [%s]: %s\n", errs.Code(err), sanitizeText(err.Error()))
	var apiError *errs.APIError
	if errors.As(err, &apiError) {
		for _, field := range sortedFieldNames(apiError.Errors) {
			if sensitiveField(field) {
				continue
			}
			for _, message := range apiError.Errors[field] {
				fmt.Fprintf(dependencies.ErrorOutput, "  %s: %s\n", field, sanitizeText(message))
			}
		}
	}
}

type problemDocument struct {
	Type      string              `json:"type"`
	Title     string              `json:"title"`
	Status    int                 `json:"status"`
	Code      string              `json:"code"`
	Detail    string              `json:"detail"`
	RequestID string              `json:"request_id"`
	Errors    map[string][]string `json:"errors"`
	Meta      map[string]any      `json:"meta"`
}

func canonicalProblem(err error) problemDocument {
	code := errs.Code(err)
	problem := problemDocument{
		Type:   "https://daemons.run/problems/" + strings.ReplaceAll(code, "_", "-"),
		Title:  problemTitle(code),
		Status: localProblemStatus(err),
		Code:   code,
		Detail: sanitizeText(err.Error()),
		Errors: map[string][]string{},
		Meta:   map[string]any{},
	}
	var apiError *errs.APIError
	if errors.As(err, &apiError) {
		problem.RequestID = apiError.RequestID
		if apiError.Errors != nil {
			problem.Errors = apiError.Errors
		}
		if apiError.Meta != nil {
			problem.Meta = apiError.Meta
		}
	}
	var cliError *errs.CLIError
	if errors.As(err, &cliError) {
		problem.RequestID = cliError.RequestID
		if cliError.OperationState != "" {
			problem.Meta["operation_state"] = cliError.OperationState
		}
	}
	return problem
}

func problemTitle(code string) string {
	title := strings.ReplaceAll(code, "_", " ")
	if title == "" {
		return "CLI error"
	}
	return strings.ToUpper(title[:1]) + title[1:]
}

func localProblemStatus(err error) int {
	var apiError *errs.APIError
	if errors.As(err, &apiError) && apiError.Status > 0 {
		return apiError.Status
	}
	switch errs.Code(err) {
	case "invalid_response":
		return 502
	case "network_error":
		return 503
	case "outcome_unknown", "wait_timeout":
		return 504
	}
	switch errs.ExitCode(err) {
	case 2:
		return 400
	case 3:
		return 401
	case 4:
		return 404
	case 5:
		return 403
	case 6:
		return 409
	case 7:
		return 429
	case 8:
		return 504
	default:
		return 500
	}
}

func sortedFieldNames(fields map[string][]string) []string {
	names := make([]string, 0, len(fields))
	for name := range fields {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

func sanitizeProblem(raw json.RawMessage) json.RawMessage {
	var value any
	if json.Unmarshal(raw, &value) != nil {
		return nil
	}
	value = sanitizeValue(value, "")
	sanitized, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	return sanitized
}

func sanitizeValue(value any, key string) any {
	switch nested := value.(type) {
	case map[string]any:
		for childKey, child := range nested {
			if sensitiveField(childKey) {
				nested[childKey] = "[REDACTED]"
				continue
			}
			nested[childKey] = sanitizeValue(child, childKey)
		}
	case []any:
		for index, child := range nested {
			nested[index] = sanitizeValue(child, key)
		}
	case string:
		return sanitizeText(nested)
	}
	return value
}

func sanitizeText(value string) string {
	return errs.Redact(value)
}

func sensitiveField(key string) bool {
	normalized := strings.ToLower(strings.ReplaceAll(key, "-", "_"))
	for _, fragment := range []string{"access_token", "refresh_token", "authorization", "credential", "password", "secret", "ticket"} {
		if strings.Contains(normalized, fragment) {
			return true
		}
	}
	return normalized == "token"
}
