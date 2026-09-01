package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestJSONLocalFailuresUseCanonicalProblemDocuments(t *testing.T) {
	t.Run("valid JSON with an incompatible shape", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			_, _ = io.WriteString(writer, `{"data":{"account":"unexpected","token":{}},"meta":[]}`)
		}))
		defer server.Close()

		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--json", "--host", server.URL, "whoami"}, dependencies)
		assertCanonicalProblem(t, output.Bytes(), errorOutput.String(), code, http.StatusBadGateway, "invalid_response")
		if strings.Contains(output.String(), "invalid JSON") {
			t.Fatalf("valid JSON was mislabeled: %s", output.String())
		}
	})

	t.Run("network failure names the selected host", func(t *testing.T) {
		httpClient := &http.Client{Transport: appRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return nil, errors.New("synthetic connection failure")
		})}
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, httpClient, &output, &errorOutput)
		code := Run(context.Background(), []string{"--json", "--host", "https://wrong.invalid", "whoami"}, dependencies)
		problem := assertCanonicalProblem(t, output.Bytes(), errorOutput.String(), code, http.StatusServiceUnavailable, "network_error")
		if detail, _ := problem["detail"].(string); !strings.Contains(detail, "https://wrong.invalid/api/v1") || strings.Contains(detail, "daemons.run Control Plane") {
			t.Fatalf("detail = %q", detail)
		}
	})
}

func TestBareWaitTimeoutAndCommandHelpContract(t *testing.T) {
	parsed, err := parseWaitTimeout("1")
	if err != nil || parsed != time.Second {
		t.Fatalf("parseWaitTimeout(1) = %s, %v", parsed, err)
	}

	var output, errorOutput bytes.Buffer
	code := Run(context.Background(), []string{"restart", "--help"}, Dependencies{
		Output:      &output,
		ErrorOutput: &errorOutput,
		Environment: map[string]string{},
	})
	if code != 0 || errorOutput.Len() != 0 || !strings.Contains(output.String(), "1s") || !strings.Contains(output.String(), "bare numbers mean seconds") {
		t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
	}
}

func assertCanonicalProblem(t *testing.T, output []byte, stderr string, exitCode, status int, code string) map[string]any {
	t.Helper()
	if exitCode != 1 || stderr != "" {
		t.Fatalf("exit = %d, stderr = %q, stdout = %s", exitCode, stderr, output)
	}
	var problem map[string]any
	if err := json.Unmarshal(output, &problem); err != nil {
		t.Fatalf("decode problem: %v", err)
	}
	if _, nested := problem["error"]; nested || problem["code"] != code || problem["status"] != float64(status) {
		t.Fatalf("problem = %#v", problem)
	}
	for _, field := range []string{"type", "title", "status", "code", "detail", "request_id", "errors", "meta"} {
		if _, exists := problem[field]; !exists {
			t.Fatalf("problem lacks %q: %#v", field, problem)
		}
	}
	return problem
}

type appRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip appRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
