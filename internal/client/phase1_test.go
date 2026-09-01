package client

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func TestLifecycleTransportFailureIsOutcomeUnknownAndIsNotRetried(t *testing.T) {
	requests := 0
	mutationKey := ""
	httpClient := &http.Client{Transport: clientRoundTripFunc(func(request *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return &http.Response{
				StatusCode: http.StatusOK,
				Header: http.Header{
					"Content-Type":          []string{"application/json"},
					"X-Daemons-Api-Version": []string{"v1"},
				},
				Body: io.NopCloser(strings.NewReader(`{"data":{"version":"v1"},"meta":{}}`)),
			}, nil
		}
		mutationKey = request.Header.Get("Idempotency-Key")
		return nil, errors.New("connection reset after dispatch")
	})}
	api, err := New("http://127.0.0.1", "dr_cp_test", WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}

	_, err = api.LifecycleDaemon(context.Background(), "daemon-uuid", "restart", "stable-restart-key")
	if errs.ExitCode(err) != 8 || errs.Code(err) != "outcome_unknown" {
		t.Fatalf("error = %v, code = %q, exit = %d", err, errs.Code(err), errs.ExitCode(err))
	}
	if requests != 2 || mutationKey != "stable-restart-key" {
		t.Fatalf("requests = %d, mutation key = %q", requests, mutationKey)
	}
}

func TestPreflightResourceVersionMismatchStopsMutation(t *testing.T) {
	mutationRequests := 0
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		if request.URL.Path == "/api/v1" {
			io.WriteString(writer, `{"data":{"version":"v2"},"meta":{}}`)
			return
		}
		mutationRequests++
	}))
	defer server.Close()

	api, err := New(server.URL, "dr_cp_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.LifecycleDaemon(context.Background(), "daemon-uuid", "start", "stable-start-key")
	if errs.ExitCode(err) != 2 || errs.Code(err) != "api_version_mismatch" || mutationRequests != 0 {
		t.Fatalf("error = %v, exit = %d, mutations = %d", err, errs.ExitCode(err), mutationRequests)
	}
}

func TestLifecycleWarningsAreVisibleAndDeduplicated(t *testing.T) {
	warnings := make([]string, 0, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		writer.Header().Set("Deprecation", "true")
		writer.Header().Set("Sunset", "Wed, 01 Oct 2026 00:00:00 GMT")
		writer.Header().Set("Link", `<https://control.example/api/v2>; rel="successor-version"`)
		io.WriteString(writer, `{"data":[],"meta":{"next_cursor":null}}`)
	}))
	defer server.Close()

	api, err := New(server.URL, "dr_cp_test", WithWarningSink(func(warning string) {
		warnings = append(warnings, warning)
	}))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.ListDaemons(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := api.ListDaemons(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "deprecation=true") || !strings.Contains(warnings[0], "sunset=") || !strings.Contains(warnings[0], "replacement=https://control.example/api/v2") {
		t.Fatalf("warnings = %#v", warnings)
	}
}

func TestRequiredResourceDiscriminatorFailsVisibly(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		io.WriteString(writer, `{"data":{"id":"server-uuid","name":"host","future_field":"kept"},"meta":{}}`)
	}))
	defer server.Close()

	api, err := New(server.URL, "dr_cp_test")
	if err != nil {
		t.Fatal(err)
	}
	_, err = api.ShowServer(context.Background(), "server-uuid")
	if errs.Code(err) != "invalid_response" || errs.ExitCode(err) != 1 {
		t.Fatalf("error = %v, code = %q, exit = %d", err, errs.Code(err), errs.ExitCode(err))
	}
}

type clientRoundTripFunc func(*http.Request) (*http.Response, error)

func (roundTrip clientRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return roundTrip(request)
}
