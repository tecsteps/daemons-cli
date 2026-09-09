package client

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"testing"
)

// Device proof on a working transport. The guest already holds this device's
// public key, so the proof carries only the challenge, the session and the
// signature: nothing a caller could substitute a key with.

type testGuestSigner struct {
	identity *ecdsa.PrivateKey
	now      int64
}

func newTestGuestSigner(t *testing.T, now int64) *testGuestSigner {
	t.Helper()
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &testGuestSigner{identity: identity, now: now}
}

func (g *testGuestSigner) pin() string {
	raw := elliptic.Marshal(elliptic.P256(), g.identity.PublicKey.X, g.identity.PublicKey.Y) //nolint:staticcheck
	digest := sha256.Sum256(raw)
	return lockHex(digest[:])
}

// challenge builds a signed working-transport challenge. overrides replace any
// field, so a test can move exactly one binding at a time.
func (g *testGuestSigner) challenge(t *testing.T, action, resource string, overrides map[string]any) string {
	t.Helper()
	recipient, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identityBytes := elliptic.Marshal(elliptic.P256(), g.identity.PublicKey.X, g.identity.PublicKey.Y) //nolint:staticcheck
	recipientBytes := elliptic.Marshal(elliptic.P256(), recipient.PublicKey.X, recipient.PublicKey.Y)  //nolint:staticcheck
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatal(err)
	}
	body := map[string]any{
		"version":                   int64(1),
		"challenge_uuid":            "88888888-8888-4888-8888-000000000001",
		"organization_uuid":         "33333333-3333-4333-8333-333333333333",
		"workspace_uuid":            "11111111-1111-4111-8111-111111111111",
		"assignment_generation":     int64(1),
		"boot_uuid":                 "44444444-4444-4444-8444-444444444444",
		"lock_epoch":                int64(1),
		"credential_revision":       int64(1),
		"lease_uuid":                "77777777-7777-4777-8777-777777777777",
		"authority_epoch":           int64(1),
		"operation_uuid":            "99999999-9999-4999-8999-000000000001",
		"action":                    action,
		"nonce":                     lockArmor(nonce),
		"expires_at":                g.now + 20000,
		"identity_public_key":       lockArmor(identityBytes),
		"recipient_public_key":      lockArmor(recipientBytes),
		"actor_subject_uuid":        "55555555-5555-4555-8555-555555555555",
		"membership_uuid":           "66666666-6666-4666-8666-666666666666",
		"policy_revision":           int64(1),
		"organization_key_revision": int64(1),
		"hold_revision":             int64(0),
		"versions": map[string]any{
			"authorization_version": int64(1), "workspace_access_version": int64(1),
			"placement_generation": int64(1), "assignment_generation": int64(1),
			"lifecycle_revision": int64(1), "host_generation": int64(1),
		},
	}
	if resource != "" {
		body["resource_uuid"] = resource
	}
	for key, value := range overrides {
		body[key] = value
	}
	canonical, err := canonicalLockJSON(body)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(lockSigningInput(LockChallengeDomain, canonical))
	r, s, err := ecdsa.Sign(rand.Reader, g.identity, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	envelope, err := canonicalLockJSON(map[string]any{
		"version": int64(1), "challenge": body, "signature": lockArmor(signature),
	})
	if err != nil {
		t.Fatal(err)
	}
	return envelope
}

func testAuthority(t *testing.T, guest *testGuestSigner, now int64) LockDeviceAuthority {
	t.Helper()
	device, err := NewLockDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	return LockDeviceAuthority{
		Device:               device,
		SessionUUID:          "22222222-2222-4222-8222-222222222222",
		IdentityPin:          guest.pin(),
		OrganizationUUID:     "33333333-3333-4333-8333-333333333333",
		WorkspaceUUID:        "11111111-1111-4111-8111-111111111111",
		BootUUID:             "44444444-4444-4444-8444-444444444444",
		ActorSubjectUUID:     "55555555-5555-4555-8555-555555555555",
		MembershipUUID:       "66666666-6666-4666-8666-666666666666",
		AssignmentGeneration: 1,
		LockEpoch:            1,
		CredentialRevision:   1,
		ExpiresAtMs:          now + 60000,
	}
}

func TestLockDeviceProofBindsEveryAuthorityField(t *testing.T) {
	const now int64 = 1_700_000_000_000
	guest := newTestGuestSigner(t, now)
	authority := testAuthority(t, guest, now)
	resource := "11111111-1111-4111-8111-111111111111"

	envelope := `{"type":"lock_device_challenge","frame":` + mustJSONString(t, guest.challenge(t, "terminal.connect", resource, nil)) + `}`
	reply, err := authority.RespondToLockDeviceChallenge(envelope, "terminal.connect", resource, now)
	if err != nil {
		t.Fatalf("a valid working challenge was refused: %v", err)
	}
	var decoded struct {
		Type  string `json:"type"`
		Proof struct {
			ChallengeUUID     string `json:"challenge_uuid"`
			DeviceSessionUUID string `json:"device_session_uuid"`
			Signature         string `json:"signature"`
		} `json:"proof"`
	}
	if err := json.Unmarshal([]byte(reply), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Type != "lock_device_proof" || decoded.Proof.DeviceSessionUUID != authority.SessionUUID {
		t.Fatalf("unexpected proof envelope: %s", reply)
	}
	if _, err := lockUnarmor(decoded.Proof.Signature, 64); err != nil {
		t.Fatal("the proof signature is not 64 raw bytes")
	}
	// The proof carries exactly three fields: no device public key travels.
	var outer struct {
		Proof map[string]any `json:"proof"`
	}
	if err := json.Unmarshal([]byte(reply), &outer); err != nil {
		t.Fatal(err)
	}
	if len(outer.Proof) != 3 {
		t.Fatalf("the proof carried %d fields: %s", len(outer.Proof), reply)
	}

	moved := map[string]func(map[string]any){
		"a new guest boot":       func(o map[string]any) { o["boot_uuid"] = "44444444-4444-4444-8444-4444444444ff" },
		"a new lock epoch":       func(o map[string]any) { o["lock_epoch"] = int64(2) },
		"a new credential":       func(o map[string]any) { o["credential_revision"] = int64(2) },
		"a different actor":      func(o map[string]any) { o["actor_subject_uuid"] = "55555555-5555-4555-8555-5555555555ff" },
		"a different membership": func(o map[string]any) { o["membership_uuid"] = "66666666-6666-4666-8666-6666666666ff" },
		"a different assignment": func(o map[string]any) { o["assignment_generation"] = int64(2) },
	}
	for name, mutate := range moved {
		t.Run(name, func(t *testing.T) {
			overrides := map[string]any{}
			mutate(overrides)
			if _, err := authority.Prove(guest.challenge(t, "terminal.connect", resource, overrides), "terminal.connect", resource, now); err == nil {
				t.Fatal("a proof was signed for a moved authority")
			}
		})
	}

	t.Run("a different resource", func(t *testing.T) {
		other := "11111111-1111-4111-8111-1111111111ff"
		if _, err := authority.Prove(guest.challenge(t, "terminal.connect", other, nil), "terminal.connect", resource, now); err == nil {
			t.Fatal("a proof was signed for another resource")
		}
	})
	t.Run("a different action", func(t *testing.T) {
		if _, err := authority.Prove(guest.challenge(t, "files.download", resource, nil), "terminal.connect", resource, now); err == nil {
			t.Fatal("a proof was signed for another action")
		}
	})
	t.Run("an expired grant", func(t *testing.T) {
		expired := authority
		expired.ExpiresAtMs = now
		if _, err := expired.Prove(guest.challenge(t, "terminal.connect", resource, nil), "terminal.connect", resource, now); err == nil {
			t.Fatal("an expired grant signed a proof")
		}
	})
	t.Run("an unpinned guest", func(t *testing.T) {
		other := newTestGuestSigner(t, now)
		if _, err := authority.Prove(other.challenge(t, "terminal.connect", resource, nil), "terminal.connect", resource, now); err == nil {
			t.Fatal("a proof was signed for an unpinned guest")
		}
	})
	t.Run("a lock challenge without a resource", func(t *testing.T) {
		if _, err := authority.Prove(guest.challenge(t, "terminal.connect", "", nil), "terminal.connect", resource, now); err == nil {
			t.Fatal("a working challenge without a resource was accepted")
		}
	})
}

func mustJSONString(t *testing.T, value string) string {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(encoded)
}
