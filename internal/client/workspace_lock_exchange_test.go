package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func exchangeServer(t *testing.T, payload string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		if request.URL.Path == "/api/v1" {
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
			return
		}
		if !strings.HasSuffix(request.URL.Path, "/lock-exchanges") {
			writer.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(writer, payload)
	}))
}

const exchangeWorkspace = "11111111-1111-4111-8111-111111111111"

func exchangePayload(t *testing.T, handoff, replacement string) string {
	t.Helper()
	return `{"data":{"version":1,"workspace_uuid":"` + exchangeWorkspace + `",` +
		`"lock":{"state":"locked","observed_at":null,"revision":4},` +
		`"actor":{"is_owner":false,"is_assignee":true},` +
		`"handoff":` + handoff + `,"replacement":` + replacement + `},"meta":{}}`
}

const validHandoff = `{"operation_uuid":"22222222-2222-4222-8222-222222222222",` +
	`"successor_membership_uuid":"33333333-3333-4333-8333-333333333333",` +
	`"old_assignment_generation":2,"new_assignment_generation":3,` +
	`"old_placement_generation":5,"new_placement_generation":5,` +
	`"preserve_data":true,"approval_recorded":false}`

const validReplacement = `{"rotation_uuid":"44444444-4444-4444-8444-444444444444",` +
	`"expected_key_revision":1,"new_key_revision":2,"confirmation_nonce_required":true}`

func TestLockExchangesAcceptsOnlyACoherentView(t *testing.T) {
	server := exchangeServer(t, exchangePayload(t, validHandoff, validReplacement))
	defer server.Close()
	api, err := New(server.URL, "dr_cp_test", WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	view, err := api.LockExchanges(context.Background(), exchangeWorkspace)
	if err != nil {
		t.Fatalf("LockExchanges() error = %v", err)
	}
	if view.Data.Lock.State != "locked" || !view.Data.Actor.IsAssignee || view.Data.Actor.IsOwner {
		t.Fatalf("view = %#v", view.Data)
	}
	if view.Data.Handoff.OperationUUID != "22222222-2222-4222-8222-222222222222" ||
		view.Data.Replacement.RotationUUID != "44444444-4444-4444-8444-444444444444" {
		t.Fatalf("bindings = %#v %#v", view.Data.Handoff, view.Data.Replacement)
	}

	for _, broken := range []struct{ name, handoff, replacement string }{
		{"skipped generation", strings.Replace(validHandoff, `"new_assignment_generation":3`, `"new_assignment_generation":4`, 1), validReplacement},
		{"moved placement", strings.Replace(validHandoff, `"new_placement_generation":5`, `"new_placement_generation":6`, 1), validReplacement},
		{"not preserving", strings.Replace(validHandoff, `"preserve_data":true`, `"preserve_data":false`, 1), validReplacement},
		{"invalid operation", strings.Replace(validHandoff, `"22222222-2222-4222-8222-222222222222"`, `"not-a-uuid"`, 1), validReplacement},
		{"skipped revision", validHandoff, strings.Replace(validReplacement, `"new_key_revision":2`, `"new_key_revision":3`, 1)},
		{"invalid rotation", validHandoff, strings.Replace(validReplacement, `"44444444-4444-4444-8444-444444444444"`, `"nope"`, 1)},
	} {
		broken := broken
		t.Run(broken.name, func(t *testing.T) {
			server := exchangeServer(t, exchangePayload(t, broken.handoff, broken.replacement))
			defer server.Close()
			api, err := New(server.URL, "dr_cp_test", WithVersion("test"))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := api.LockExchanges(context.Background(), exchangeWorkspace); err == nil {
				t.Fatal("an incoherent view was accepted")
			}
		})
	}
}

func TestLockExchangesRejectsAnotherWorkspace(t *testing.T) {
	server := exchangeServer(t, strings.Replace(exchangePayload(t, "null", "null"),
		exchangeWorkspace, "99999999-9999-4999-8999-999999999999", 1))
	defer server.Close()
	api, err := New(server.URL, "dr_cp_test", WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := api.LockExchanges(context.Background(), exchangeWorkspace); err == nil {
		t.Fatal("a view for another workspace was accepted")
	}
}

func TestHandoffBodyBindsTheGuestChallengeNotTheControlPlane(t *testing.T) {
	successor := "33333333-3333-4333-8333-333333333333"
	scope := &LockHandoffScope{OperationUUID: "22222222-2222-4222-8222-222222222222",
		SuccessorMembershipUUID: &successor, OldAssignmentGeneration: 2, NewAssignmentGeneration: 3,
		OldPlacementGeneration: 5, NewPlacementGeneration: 5, PreserveData: true}
	challenge := LockChallenge{OrganizationUUID: "55555555-5555-4555-8555-555555555555",
		WorkspaceUUID: exchangeWorkspace, AssignmentGeneration: 2}

	body, err := LockHandoffBody("0042", "", scope, challenge)
	if err != nil {
		t.Fatalf("LockHandoffBody() error = %v", err)
	}
	encoded, _ := json.Marshal(body["handoff_scope"])
	var got map[string]any
	if err := json.Unmarshal(encoded, &got); err != nil {
		t.Fatal(err)
	}
	if got["organization_uuid"] != challenge.OrganizationUUID || got["workspace_uuid"] != exchangeWorkspace {
		t.Fatalf("scope identity = %v, want the guest's own challenge", got)
	}
	if body["credential_type"] != "pin" || body["secret"] != "0042" {
		t.Fatalf("factor = %v", body)
	}

	// A challenge from a different generation is a different reassignment.
	if _, err := LockHandoffBody("0042", "", scope, LockChallenge{OrganizationUUID: challenge.OrganizationUUID,
		WorkspaceUUID: exchangeWorkspace, AssignmentGeneration: 3}); err == nil {
		t.Fatal("a stale scope was approved")
	}
	// Exactly one factor, and never a missing scope.
	if _, err := LockHandoffBody("0042", "phrase", scope, challenge); err == nil {
		t.Fatal("two factors were accepted")
	}
	if _, err := LockHandoffBody("", "", scope, challenge); err == nil {
		t.Fatal("no factor was accepted")
	}
	if _, err := LockHandoffBody("0042", "", nil, challenge); err == nil {
		t.Fatal("a missing scope was accepted")
	}
	phraseBody, err := LockHandoffBody("", "0123456789abcdef", scope, challenge)
	if err != nil || phraseBody["credential_type"] != "recovery_phrase" {
		t.Fatalf("phrase body = %v, err = %v", phraseBody, err)
	}
}

func TestReplacementBodyNeedsTheOwnerConfirmationCode(t *testing.T) {
	pending := &LockReplacementPending{RotationUUID: "44444444-4444-4444-8444-444444444444",
		ExpectedKeyRevision: 1, NewKeyRevision: 2, ConfirmationNonceNeeded: true}
	nonce := strings.Repeat("A", 43)

	body, err := LockReplacementBody("0042", "", nonce, pending)
	if err != nil {
		t.Fatalf("LockReplacementBody() error = %v", err)
	}
	if body["rotation_uuid"] != pending.RotationUUID || body["confirmation_nonce"] != nonce ||
		body["expected_key_revision"] != int64(1) || body["new_key_revision"] != int64(2) {
		t.Fatalf("body = %v", body)
	}
	for _, invalid := range []string{"", "short", strings.Repeat("A", 44), strings.Repeat("=", 43)} {
		if _, err := LockReplacementBody("0042", "", invalid, pending); err == nil {
			t.Fatalf("confirmation code %q was accepted", invalid)
		}
	}
	if _, err := LockReplacementBody("0042", "", nonce, nil); err == nil {
		t.Fatal("a replacement that is not pending was authorized")
	}
}
