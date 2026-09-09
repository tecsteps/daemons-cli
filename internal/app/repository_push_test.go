package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/client"
)

const pushDaemonUUID = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
const pushRequestUUID = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb"

func TestPushRequestUsesOnlyGuestSelectorsAndNeverRetriesAmbiguousAcknowledgements(t *testing.T) {
	for _, body := range []string{
		`{"request_uuid":"` + pushRequestUUID + `","state":"pending"}`,
		`{"request_uuid":"` + pushRequestUUID + `","state":"approved"}`,
		`{"request_uuid":"` + pushRequestUUID + `","state":"pending","content":"private-canary"}`,
		`{"request_uuid":"` + pushRequestUUID + `","state":"pending","state":"pending"}`,
	} {
		t.Run(body, func(t *testing.T) {
			metadataCalls, guestCalls := 0, 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Daemons-Api-Version", "v1")
				if r.URL.Path == "/api/v1" {
					io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
					return
				}
				if r.URL.Path == "/api/v1/daemons/"+pushDaemonUUID+"/access-tickets" {
					metadataCalls++
					var metadata map[string]string
					json.NewDecoder(r.Body).Decode(&metadata)
					if len(metadata) != 3 || metadata["resource_uuid"] != pushRequestUUID || metadata["action"] != "repository.prepare" {
						t.Error("central selector boundary")
					}
					json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ticket": "opaque.ticket", "ticket_version": 2, "expires_in": 30, "method": "POST", "gateway_path": "/v1/workspaces/" + pushDaemonUUID + "/repositories/" + pushRequestUUID + "/prepare"}})
					return
				}
				guestCalls++
				if r.URL.Path != "/v1/workspaces/"+pushDaemonUUID+"/repositories/"+pushRequestUUID+"/prepare" || r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
					t.Error("wrong guest transport")
				}
				var selector map[string]string
				json.NewDecoder(r.Body).Decode(&selector)
				if len(selector) != 2 || selector["repository_uuid"] != pushRequestUUID || selector["local_branch"] != "private-branch-canary" {
					t.Error("wrong guest selector")
				}
				io.WriteString(w, body)
			}))
			defer server.Close()
			var out, stderr bytes.Buffer
			code := Run(context.Background(), []string{"--host", server.URL, "--json", "push", "request", pushDaemonUUID, pushRequestUUID, "private-branch-canary"}, phaseOneDependencies(t, server.Client(), &out, &stderr))
			valid := body == `{"request_uuid":"`+pushRequestUUID+`","state":"pending"}`
			if metadataCalls != 1 || guestCalls != 1 || (valid && code != 0) || (!valid && code != 8) {
				t.Fatalf("code=%d metadata=%d guest=%d error=%s", code, metadataCalls, guestCalls, stderr.String())
			}
			if strings.Contains(out.String()+stderr.String(), "private-canary") || strings.Contains(out.String()+stderr.String(), "private-branch-canary") {
				t.Error("private selector or response content escaped")
			}
		})
	}
}

// A preparation the control plane refuses created nothing, so it must not be reported as
// ambiguous: telling the engineer to check the list before retrying would be false, and exit 8
// is the code that means "an attempt may exist". The budget, the authority fences and the
// closed qualification gate all refuse before a request row exists.
func TestPushRequestRefusedBeforeCreationIsNotAmbiguous(t *testing.T) {
	for _, refusal := range []struct {
		name   string
		status int
		code   string
		want   int
	}{
		{name: "preparation budget", status: 429, code: "request_conflict", want: 7},
		{name: "authority changed", status: 409, code: "stale_generation", want: 1},
		{name: "protection unavailable", status: 503, code: "protection_unavailable", want: 1},
		{name: "not the assignee", status: 403, code: "forbidden", want: 5},
	} {
		t.Run(refusal.name, func(t *testing.T) {
			guestCalls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Daemons-Api-Version", "v1")
				if r.URL.Path == "/api/v1" {
					io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
					return
				}
				if r.URL.Path == "/api/v1/daemons/"+pushDaemonUUID+"/access-tickets" {
					w.WriteHeader(refusal.status)
					io.WriteString(w, `{"code":"`+refusal.code+`"}`)
					return
				}
				guestCalls++
			}))
			defer server.Close()
			var out, stderr bytes.Buffer
			code := Run(context.Background(), []string{"--host", server.URL, "push", "request", pushDaemonUUID, pushRequestUUID, "private-branch-canary"}, phaseOneDependencies(t, server.Client(), &out, &stderr))
			if code != refusal.want || code == 8 {
				t.Fatalf("code=%d want=%d error=%s", code, refusal.want, stderr.String())
			}
			if guestCalls != 0 {
				t.Error("a refused ticket must never reach the guest")
			}
			if strings.Contains(out.String()+stderr.String(), "private-branch-canary") {
				t.Error("the private selector escaped a refusal")
			}
		})
	}
}

func pushFixture() client.RepositoryPush {
	one := int64(1)
	return client.RepositoryPush{RequestUUID: pushRequestUUID, AssignedSubjectUUID: pushDaemonUUID,
		RepositoryUUID: pushDaemonUUID, PolicyRevisionUUID: pushDaemonUUID, State: "unknown", Version: 4,
		StatsStatus: "complete", CommitCount: &one, FilesChanged: &one, Insertions: &one, Deletions: &one,
		RequestedAt: "2026-09-08T12:00:00Z", ExpiresAt: "2026-09-08T12:15:00Z"}
}

func TestPushListAndShowUseMetadataOnly(t *testing.T) {
	for _, subcommand := range []string{"list", "show"} {
		t.Run(subcommand, func(t *testing.T) {
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Daemons-Api-Version", "v1")
				w.Header().Set("Content-Type", "application/json")
				if r.URL.Path == "/api/v1" {
					io.WriteString(w, `{"data":{"version":"v1"},"meta":{}}`)
					return
				}
				calls++
				if r.Method != http.MethodGet || r.URL.Path != "/api/v1/daemons/"+pushDaemonUUID+"/push-requests" {
					t.Error("unexpected push transport")
				}
				json.NewEncoder(w).Encode(client.RepositoryPushList{Data: []client.RepositoryPush{pushFixture()}})
			}))
			defer server.Close()
			var out, stderr bytes.Buffer
			deps := phaseOneDependencies(t, server.Client(), &out, &stderr)
			args := []string{"--host", server.URL, "--json", "push", subcommand, pushDaemonUUID}
			if subcommand == "show" {
				args = append(args, pushRequestUUID)
			}
			code := Run(context.Background(), args, deps)
			if code != 0 || calls != 1 || !json.Valid(out.Bytes()) || !strings.Contains(out.String(), `"state":"unknown"`) {
				t.Fatalf("read failed: exit=%d calls=%d stderr=%s", code, calls, stderr.String())
			}
		})
	}
}

func TestPushShowFollowsBoundedMetadataCursor(t *testing.T) {
	requests := 0
	last := ""
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		if r.URL.Path == "/api/v1" {
			io.WriteString(w, `{"data":{"version":"v1"}}`)
			return
		}
		requests++
		if requests == 1 {
			page := client.RepositoryPushList{Data: []client.RepositoryPush{}}
			for n := 1; n <= 50; n++ {
				item := pushFixture()
				item.RequestUUID = fmt.Sprintf("%08x-aaaa-4aaa-8aaa-aaaaaaaaaaaa", n)
				page.Data = append(page.Data, item)
			}
			last = page.Data[49].RequestUUID
			page.NextCursor = &last
			json.NewEncoder(w).Encode(page)
		} else {
			if r.URL.Query().Get("cursor") != last {
				t.Error("missing continuation cursor")
			}
			json.NewEncoder(w).Encode(client.RepositoryPushList{Data: []client.RepositoryPush{pushFixture()}})
		}
	}))
	defer server.Close()
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--host", server.URL, "push", "show", pushDaemonUUID, pushRequestUUID}, phaseOneDependencies(t, server.Client(), &out, &stderr))
	if code != 0 || requests != 2 || !strings.Contains(out.String(), "State: unknown") {
		t.Fatalf("lookup failed: exit=%d calls=%d stderr=%s", code, requests, stderr.String())
	}
}

func TestPushRejectsApprovalFlagsAndInvalidSelectorsWithoutNetwork(t *testing.T) {
	for _, args := range [][]string{
		{"push", "request", pushDaemonUUID, "1", "feature"},
		{"push", "request", pushDaemonUUID, pushRequestUUID, "feature~1"},
		{"push", "request", pushDaemonUUID, pushRequestUUID, "feature", "--yes"},
		{"push", "approve", pushDaemonUUID, pushRequestUUID}, {"push", "list", pushDaemonUUID, "--yes"},
		{"push", "show", pushDaemonUUID, "1"}, {"push", "list", pushDaemonUUID, "--cursor", "1"},
		{"push", "list", "--yes"}, {"push", "show", pushDaemonUUID, pushRequestUUID, "--yes"},
	} {
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			requests := 0
			server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests++ }))
			defer server.Close()
			var out, stderr bytes.Buffer
			code := Run(context.Background(), append([]string{"--host", server.URL}, args...), phaseOneDependencies(t, server.Client(), &out, &stderr))
			if code != 2 || requests != 0 {
				t.Fatalf("unsafe command: exit=%d calls=%d", code, requests)
			}
		})
	}
}

func TestPushReadDoesNotRetryUnavailableAuthority(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		if r.URL.Path == "/api/v1" {
			io.WriteString(w, `{"data":{"version":"v1"}}`)
			return
		}
		requests++
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"protection_unavailable"}`)
	}))
	defer server.Close()
	var out, stderr bytes.Buffer
	code := Run(context.Background(), []string{"--host", server.URL, "push", "list", pushDaemonUUID}, phaseOneDependencies(t, server.Client(), &out, &stderr))
	if code == 0 || requests != 1 {
		t.Fatalf("unexpected retry: exit=%d calls=%d", code, requests)
	}
}
