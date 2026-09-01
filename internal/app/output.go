package app

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

var credentialValuePattern = regexp.MustCompile(`(?i)(?:bearer[ \t]+)?dr_(?:cp|agent|terminal|ticket)_[A-Za-z0-9._~-]+`)

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
			writeCanonicalJSON(dependencies.Output, sanitizeProblem(raw))
			return
		}
		writeJSON(dependencies.Output, map[string]any{"error": map[string]any{"code": errs.Code(err), "message": sanitizeText(err.Error())}})
		return
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Error [%s]: %s\n", errs.Code(err), sanitizeText(err.Error()))
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
	return credentialValuePattern.ReplaceAllString(value, "[REDACTED]")
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
