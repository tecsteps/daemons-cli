package client

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cloudflare/circl/hpke"
)

// The shared E22 vectors are the contract between this Go client, the guest's
// Node adapter and the browser's WebCrypto adapter. They are copied fixtures,
// not generated here: a change in either direction must fail this test.
//
// Private keys in the fixtures are deliberately public synthetic material and
// are never used at runtime.

func loadVector(t *testing.T, name string, target any) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "e22", name))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatal(err)
	}
}

func unhex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return decoded
}

func lockSuite() hpke.Suite {
	return hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
}

// guestOpener plays the guest: it holds the recipient private key and opens
// what this client sealed.
func guestOpener(t *testing.T, privateHex, encArmored, info string) hpke.Opener {
	t.Helper()
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	private, err := scheme.UnmarshalBinaryPrivateKey(unhex(t, privateHex))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := lockSuite().NewReceiver(private, []byte(info))
	if err != nil {
		t.Fatal(err)
	}
	enc, err := base64.RawURLEncoding.Strict().DecodeString(encArmored)
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(enc)
	if err != nil {
		t.Fatal(err)
	}
	return opener
}

// TestRFC9180BaseModeVectors proves the approved CIRCL dependency computes the
// CFRG base-mode 16/1/1 encryptions and exporters, the same suite the guest and
// browser use.
func TestRFC9180BaseModeVectors(t *testing.T) {
	var vector struct {
		SkRm, Enc, Info string
		Encryptions     []struct{ AAD, Ct, Pt string }
		Exports         []struct {
			Context string `json:"exporter_context"`
			Length  int    `json:"L"`
			Value   string `json:"exported_value"`
		}
	}
	loadVector(t, "rfc9180-p256.json", &vector)
	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	private, err := scheme.UnmarshalBinaryPrivateKey(unhex(t, vector.SkRm))
	if err != nil {
		t.Fatal(err)
	}
	receiver, err := lockSuite().NewReceiver(private, unhex(t, vector.Info))
	if err != nil {
		t.Fatal(err)
	}
	opener, err := receiver.Setup(unhex(t, vector.Enc))
	if err != nil {
		t.Fatal(err)
	}
	for index, item := range vector.Encryptions {
		plain, err := opener.Open(unhex(t, item.Ct), unhex(t, item.AAD))
		if err != nil || !bytes.Equal(plain, unhex(t, item.Pt)) {
			t.Fatalf("CFRG encryption %d does not match the vector: %v", index, err)
		}
	}
	for index, item := range vector.Exports {
		if value := opener.Export(unhex(t, item.Context), uint(item.Length)); !bytes.Equal(value, unhex(t, item.Value)) {
			t.Fatalf("CFRG exporter %d does not match the vector", index)
		}
	}
}

type lockVector struct {
	Challenge          map[string]any  `json:"challenge"`
	CanonicalChallenge string          `json:"canonical_challenge"`
	Signature          string          `json:"signature"`
	RecipientPrivate   string          `json:"recipient_private_key"`
	Info               string          `json:"info"`
	Plaintext          string          `json:"plaintext"`
	Frame              string          `json:"frame"`
	ResponseKey        string          `json:"response_key"`
	ResponseNonce      string          `json:"response_nonce"`
	ResponseAAD        string          `json:"response_aad"`
	ResponsePlaintext  string          `json:"response_plaintext"`
	ResponseCiphertext string          `json:"response_ciphertext"`
	Pin                string          `json:"pin"`
	Raw                json.RawMessage `json:"-"`
}

func loadLockVector(t *testing.T) lockVector {
	t.Helper()
	var vector lockVector
	loadVector(t, "workspace-lock-v1.json", &vector)
	return vector
}

// signedEnvelope rebuilds the wire envelope the guest sends, from the fixture's
// challenge object and its hex signature.
func signedEnvelope(t *testing.T, vector lockVector) string {
	t.Helper()
	challenge, err := parseCanonicalLockJSON(vector.CanonicalChallenge, LockFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	text, err := canonicalLockJSON(map[string]any{
		"version":   int64(1),
		"challenge": challenge,
		"signature": lockArmor(unhex(t, vector.Signature)),
	})
	if err != nil {
		t.Fatal(err)
	}
	return text
}

func vectorScope(vector lockVector) LockScope {
	return LockScope{
		OrganizationUUID:     vector.Challenge["organization_uuid"].(string),
		WorkspaceUUID:        vector.Challenge["workspace_uuid"].(string),
		AssignmentGeneration: 1,
		Action:               "lock.unlock",
	}
}

func vectorNow(vector lockVector) int64 {
	return int64(vector.Challenge["expires_at"].(float64)) - 1000
}

// TestWorkspaceLockChallengeVector proves canonicalization, the pin digest and
// the ECDSA challenge domain match the guest that produced the fixture.
func TestWorkspaceLockChallengeVector(t *testing.T) {
	vector := loadLockVector(t)
	envelope := signedEnvelope(t, vector)
	challenge, err := VerifyLockChallenge(envelope, VerifyLockChallengeOptions{
		IdentityPin: vector.Pin,
		Scope:       vectorScope(vector),
		NowMs:       vectorNow(vector),
	})
	if err != nil {
		t.Fatalf("the shared challenge vector did not verify: %v", err)
	}
	if challenge.Canonical != vector.CanonicalChallenge {
		t.Fatal("canonical challenge bytes differ from the shared vector")
	}
	if challenge.IdentityPin() != vector.Pin {
		t.Fatal("identity pin differs from the shared vector")
	}
	if challenge.Action != "lock.unlock" || challenge.ResourceUUID != "" {
		t.Fatal("a lock challenge must not carry a resource")
	}
}

// TestWorkspaceLockChallengeRefusals covers the tamper cases the guest relies on
// this client to refuse before a PIN is ever encrypted.
func TestWorkspaceLockChallengeRefusals(t *testing.T) {
	vector := loadLockVector(t)
	envelope := signedEnvelope(t, vector)
	scope := vectorScope(vector)
	now := vectorNow(vector)

	valid := VerifyLockChallengeOptions{IdentityPin: vector.Pin, Scope: scope, NowMs: now}
	cases := map[string]func() (string, VerifyLockChallengeOptions){
		"a flipped signature byte": func() (string, VerifyLockChallengeOptions) {
			forged := unhex(t, vector.Signature)
			forged[10] ^= 1
			text, err := canonicalLockJSON(map[string]any{
				"version":   int64(1),
				"challenge": mustParse(t, vector.CanonicalChallenge),
				"signature": lockArmor(forged),
			})
			if err != nil {
				t.Fatal(err)
			}
			return text, valid
		},
		"a substituted context field": func() (string, VerifyLockChallengeOptions) {
			body := mustParse(t, vector.CanonicalChallenge)
			body["lock_epoch"] = json.Number("2")
			text, err := canonicalLockJSON(map[string]any{
				"version": int64(1), "challenge": body,
				"signature": lockArmor(unhex(t, vector.Signature)),
			})
			if err != nil {
				t.Fatal(err)
			}
			return text, valid
		},
		"a different pin": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.IdentityPin = strings.Repeat("ab", 32)
			return envelope, options
		},
		"a different workspace": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.Scope.WorkspaceUUID = "00000000-0000-4000-8000-0000000000ff"
			return envelope, options
		},
		"a different assignment generation": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.Scope.AssignmentGeneration = 2
			return envelope, options
		},
		"a different action": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.Scope.Action = "lock.status"
			return envelope, options
		},
		"an expired challenge": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.NowMs = int64(vector.Challenge["expires_at"].(float64))
			return envelope, options
		},
		"a challenge valid for longer than thirty seconds": func() (string, VerifyLockChallengeOptions) {
			options := valid
			options.NowMs = int64(vector.Challenge["expires_at"].(float64)) - LockChallengeLifetimeMs - 1
			return envelope, options
		},
		"noncanonical wire bytes": func() (string, VerifyLockChallengeOptions) {
			return " " + envelope, valid
		},
		"a duplicated JSON key": func() (string, VerifyLockChallengeOptions) {
			return strings.Replace(envelope, `"version":1`, `"version":1,"version":1`, 1), valid
		},
		"an oversized frame": func() (string, VerifyLockChallengeOptions) {
			return envelope + strings.Repeat(" ", LockFrameLimit), valid
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			text, options := build()
			if _, err := VerifyLockChallenge(text, options); err == nil {
				t.Fatal("the client accepted a challenge it must refuse")
			}
		})
	}
}

func mustParse(t *testing.T, text string) map[string]any {
	t.Helper()
	value, err := parseCanonicalLockJSON(text, LockFrameLimit)
	if err != nil {
		t.Fatal(err)
	}
	return value
}

// TestWorkspaceLockRequestVector opens the fixture's sealed request with the
// guest's private key, proving this client's HPKE suite, info label and AAD
// match the adapter that produced it.
func TestWorkspaceLockRequestVector(t *testing.T) {
	vector := loadLockVector(t)
	frame := mustParse(t, vector.Frame)
	opener := guestOpener(t, vector.RecipientPrivate, frame["enc"].(string), vector.Info)
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(frame["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := opener.Open(ciphertext, []byte(vector.CanonicalChallenge))
	if err != nil || string(plaintext) != vector.Plaintext {
		t.Fatalf("the shared request vector did not open: %v", err)
	}
	if key := opener.Export([]byte(lockResponseKeyLabel), 16); !bytes.Equal(key, unhex(t, vector.ResponseKey)) {
		t.Fatal("the exported response key differs from the shared vector")
	}
	if nonce := opener.Export([]byte(lockResponseNonceLabel), 12); !bytes.Equal(nonce, unhex(t, vector.ResponseNonce)) {
		t.Fatal("the exported response nonce differs from the shared vector")
	}
	digest := sha256.Sum256([]byte(vector.Frame))
	expected := append([]byte(vector.CanonicalChallenge), digest[:]...)
	if !bytes.Equal(expected, unhex(t, vector.ResponseAAD)) {
		t.Fatal("the response AAD construction differs from the shared vector")
	}
}

// TestWorkspaceLockResponseVector opens the fixture's response through the real
// LockExchange, so the AAD, exporter labels and result validation are the ones
// the commands use.
func TestWorkspaceLockResponseVector(t *testing.T) {
	vector := loadLockVector(t)
	challenge, err := VerifyLockChallenge(signedEnvelope(t, vector), VerifyLockChallengeOptions{
		IdentityPin: vector.Pin, Scope: vectorScope(vector), NowMs: vectorNow(vector),
	})
	if err != nil {
		t.Fatal(err)
	}
	exchange := &LockExchange{
		Challenge:     challenge,
		Frame:         vector.Frame,
		responseKey:   unhex(t, vector.ResponseKey),
		responseNonce: unhex(t, vector.ResponseNonce),
		requestDigest: sha256.Sum256([]byte(vector.Frame)),
	}
	responseFrame, err := canonicalLockJSON(map[string]any{
		"version":        int64(1),
		"challenge_uuid": challenge.ChallengeUUID,
		"ciphertext":     lockArmor(unhex(t, vector.ResponseCiphertext)),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := exchange.Open(responseFrame)
	if err != nil {
		t.Fatalf("the shared response vector did not open: %v", err)
	}
	decoded, err := canonicalLockJSON(result)
	if err != nil || decoded != vector.ResponsePlaintext {
		t.Fatalf("the response plaintext differs from the shared vector: %v", err)
	}
	unlocked, err := ReadLockUnlockResult(result, vectorNow(vector))
	if err != nil {
		t.Fatalf("the vector's unlock result was refused: %v", err)
	}
	if unlocked.Outcome != "unlocked" || unlocked.DeviceSessionUUID != "00000000-0000-4000-8000-000000000009" {
		t.Fatal("the unlock result was decoded incorrectly")
	}
	if _, err := exchange.Open(responseFrame); err == nil {
		t.Fatal("a second response was opened on one exchange")
	}
}

// TestWorkspaceLockRoundTrip seals a request with this client and opens it as
// the guest, then seals the guest's reply and opens it back. It proves both
// directions without depending on the fixture's ephemeral key.
func TestWorkspaceLockRoundTrip(t *testing.T) {
	vector := loadLockVector(t)
	challenge, err := VerifyLockChallenge(signedEnvelope(t, vector), VerifyLockChallengeOptions{
		IdentityPin: vector.Pin, Scope: vectorScope(vector), NowMs: vectorNow(vector),
	})
	if err != nil {
		t.Fatal(err)
	}
	device, err := NewLockDeviceKey()
	if err != nil {
		t.Fatal(err)
	}
	body, err := LockUnlockBody("0042")
	if err != nil {
		t.Fatal(err)
	}
	exchange, err := SealLockRequest(challenge, device, body)
	if err != nil {
		t.Fatal(err)
	}
	frame := mustParse(t, exchange.Frame)
	opener := guestOpener(t, vector.RecipientPrivate, frame["enc"].(string), LockProtocolLabel)
	ciphertext, err := base64.RawURLEncoding.Strict().DecodeString(frame["ciphertext"].(string))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := opener.Open(ciphertext, []byte(challenge.Canonical))
	if err != nil {
		t.Fatalf("the guest could not open this client's request: %v", err)
	}
	request := mustParse(t, string(plaintext))
	if request["secret"] != "0042" || request["action"] != "lock.unlock" ||
		request["operation_uuid"] != challenge.OperationUUID ||
		request["device_public_key"] != device.PublicKey() {
		t.Fatal("the sealed request body is not the one the contract fixes")
	}

	// The guest replies with the exported key and nonce over the request digest.
	digest := sha256.Sum256([]byte(exchange.Frame))
	aad := append([]byte(challenge.Canonical), digest[:]...)
	reply, err := canonicalLockJSON(map[string]any{
		"action": "lock.unlock", "operation_uuid": challenge.OperationUUID,
		"outcome": "unlocked", "device_session_uuid": "00000000-0000-4000-8000-00000000000a",
		"expires_at": vectorNow(vector) + 3600000,
	})
	if err != nil {
		t.Fatal(err)
	}
	aead, err := hpke.AEAD_AES128GCM.New(opener.Export([]byte(lockResponseKeyLabel), 16))
	if err != nil {
		t.Fatal(err)
	}
	sealed := aead.Seal(nil, opener.Export([]byte(lockResponseNonceLabel), 12), []byte(reply), aad)
	responseFrame, err := canonicalLockJSON(map[string]any{
		"version": int64(1), "challenge_uuid": challenge.ChallengeUUID,
		"ciphertext": lockArmor(sealed),
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := exchange.Open(responseFrame)
	if err != nil {
		t.Fatalf("this client could not open the guest's reply: %v", err)
	}
	unlocked, err := ReadLockUnlockResult(result, vectorNow(vector))
	if err != nil || unlocked.DeviceSessionUUID != "00000000-0000-4000-8000-00000000000a" {
		t.Fatalf("the round-tripped unlock result was refused: %v", err)
	}
}

// TestWorkspaceLockResponseRefusals covers the response tampering the guest
// relies on this client to detect.
func TestWorkspaceLockResponseRefusals(t *testing.T) {
	vector := loadLockVector(t)
	challenge, err := VerifyLockChallenge(signedEnvelope(t, vector), VerifyLockChallengeOptions{
		IdentityPin: vector.Pin, Scope: vectorScope(vector), NowMs: vectorNow(vector),
	})
	if err != nil {
		t.Fatal(err)
	}
	build := func(mutate func(map[string]any), digest [32]byte) string {
		frame := map[string]any{
			"version": int64(1), "challenge_uuid": challenge.ChallengeUUID,
			"ciphertext": lockArmor(unhex(t, vector.ResponseCiphertext)),
		}
		mutate(frame)
		text, err := canonicalLockJSON(frame)
		if err != nil {
			t.Fatal(err)
		}
		return text
	}
	fresh := func(digest [32]byte) *LockExchange {
		return &LockExchange{
			Challenge: challenge, Frame: vector.Frame,
			responseKey:   unhex(t, vector.ResponseKey),
			responseNonce: unhex(t, vector.ResponseNonce),
			requestDigest: digest,
		}
	}
	correct := sha256.Sum256([]byte(vector.Frame))
	wrong := sha256.Sum256([]byte(vector.Frame + " "))

	if _, err := fresh(wrong).Open(build(func(map[string]any) {}, correct)); err == nil {
		t.Fatal("a response bound to a different request frame was accepted")
	}
	if _, err := fresh(correct).Open(build(func(frame map[string]any) {
		frame["challenge_uuid"] = "00000000-0000-4000-8000-0000000000ff"
	}, correct)); err == nil {
		t.Fatal("a response for a different challenge was accepted")
	}
	if _, err := fresh(correct).Open(build(func(frame map[string]any) {
		bytes := unhex(t, vector.ResponseCiphertext)
		bytes[3] ^= 1
		frame["ciphertext"] = lockArmor(bytes)
	}, correct)); err == nil {
		t.Fatal("a tampered response ciphertext was accepted")
	}
	if _, err := fresh(correct).Open(build(func(frame map[string]any) {
		frame["extra"] = "x"
	}, correct)); err == nil {
		t.Fatal("a response with an unknown field was accepted")
	}
}

// TestCanonicalLockJSONMatchesJSONStringify pins the hand-written RFC 8785
// escaper against the browser's JSON.stringify. The expected bytes were taken
// from Node: HTML characters and astral planes stay literal, so an organization
// password round-trips identically in both clients.
func TestCanonicalLockJSONMatchesJSONStringify(t *testing.T) {
	encoded, err := canonicalLockJSON(map[string]any{"secret": "a<b&c \"\té\U0001F600"})
	if err != nil {
		t.Fatal(err)
	}
	if encoded != "{\"secret\":\"a<b&c \\\"\\té\U0001F600\"}" {
		t.Fatalf("canonical JSON differs from JSON.stringify: %s", encoded)
	}
	for _, control := range []struct {
		value    string
		expected string
	}{
		{"\x00", `{"secret":"\u0000"}`},
		{"\x1f", `{"secret":"\u001f"}`},
		{"\n", `{"secret":"\n"}`},
		{"\r", `{"secret":"\r"}`},
		{"\b", `{"secret":"\b"}`},
		{"\f", `{"secret":"\f"}`},
		{`\`, `{"secret":"\\"}`},
	} {
		encoded, err := canonicalLockJSON(map[string]any{"secret": control.value})
		if err != nil || encoded != control.expected {
			t.Fatalf("control escaping differs: %q -> %q", control.value, encoded)
		}
	}
	// Keys sort by their UTF-16 code units, which for the closed ASCII field
	// names is plain byte order.
	sorted, err := canonicalLockJSON(map[string]any{"b": int64(2), "a": int64(1), "A": int64(0)})
	if err != nil || sorted != `{"A":0,"a":1,"b":2}` {
		t.Fatalf("keys are not canonically ordered: %s", sorted)
	}
}

// TestCanonicalLockJSONRefusesNoncanonicalInput proves the round-trip equality
// check does the work the contract expects of it.
func TestCanonicalLockJSONRefusesNoncanonicalInput(t *testing.T) {
	for name, text := range map[string]string{
		"a duplicate key":       `{"a":1,"a":2}`,
		"unsorted keys":         `{"b":1,"a":2}`,
		"inserted whitespace":   `{"a": 1}`,
		"a trailing newline":    "{\"a\":1}\n",
		"a byte order mark":     "\ufeff{\"a\":1}",
		"a noncanonical zero":   `{"a":1.0}`,
		"an exponent":           `{"a":1e2}`,
		"an unsafe integer":     `{"a":9007199254740992}`,
		"invalid UTF-8":         "{\"a\":\"\xff\"}",
		"an unpaired surrogate": `{"a":"\ud800"}`,
		"a top-level array":     `[1]`,
		"trailing content":      `{"a":1}{}`,
	} {
		if _, err := parseCanonicalLockJSON(text, LockFrameLimit); err == nil {
			t.Errorf("%s was accepted as canonical", name)
		}
	}
	if _, err := parseCanonicalLockJSON(`{"a":1,"b":{"c":"x"}}`, LockFrameLimit); err != nil {
		t.Fatalf("canonical input was refused: %v", err)
	}
}
