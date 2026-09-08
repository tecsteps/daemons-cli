package app

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/cloudflare/circl/hpke"
	"github.com/cloudflare/circl/kem"
	"github.com/coder/websocket"
)

// A fake guest that speaks the real E22 wire protocol. It is written
// independently of internal/client on purpose: its canonical JSON, its
// signature domain and its HPKE handling are a second implementation, so these
// tests fail if either side drifts from the frozen contract.

const (
	lockTestWorkspace  = "11111111-1111-4111-8111-111111111111"
	lockTestPIN        = "482913"
	lockTestSession    = "22222222-2222-4222-8222-222222222222"
	lockTestOrgUUID    = "33333333-3333-4333-8333-333333333333"
	lockTestBootUUID   = "44444444-4444-4444-8444-444444444444"
	lockTestSubject    = "55555555-5555-4555-8555-555555555555"
	lockTestMembership = "66666666-6666-4666-8666-666666666666"
	lockTestLease      = "77777777-7777-4777-8777-777777777777"
)

type lockGuest struct {
	identity   *ecdsa.PrivateKey
	nowMs      int64
	pin        string
	generation int64
	// admittedActions limits what the fake Control Plane mints, mirroring the
	// production capability map.
	admittedActions map[string]bool
	pendingAction   string
	challenges      int
	lastRequest     map[string]any
}

func newLockGuest(t *testing.T, nowMs int64) *lockGuest {
	t.Helper()
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &lockGuest{
		identity: identity, nowMs: nowMs, pin: lockTestPIN, generation: 1,
		admittedActions: map[string]bool{"lock.unlock": true},
	}
}

func (g *lockGuest) identityPin() string {
	raw := elliptic.Marshal(elliptic.P256(), g.identity.PublicKey.X, g.identity.PublicKey.Y) //nolint:staticcheck
	digest := sha256.Sum256(raw)
	return fmt.Sprintf("%x", digest)
}

func (g *lockGuest) rotateIdentity(t *testing.T) {
	t.Helper()
	identity, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	g.identity = identity
}

// canonical is an independent RFC 8785 serializer for the closed lock schemas.
func canonical(value any) string {
	switch typed := value.(type) {
	case string:
		encoded, _ := json.Marshal(typed)
		return string(encoded)
	case int64:
		return strconv.FormatInt(typed, 10)
	case int:
		return strconv.Itoa(typed)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, key := range keys {
			name, _ := json.Marshal(key)
			parts = append(parts, string(name)+":"+canonical(typed[key]))
		}
		return "{" + strings.Join(parts, ",") + "}"
	}
	panic("unsupported canonical value")
}

func armor(value []byte) string { return base64.RawURLEncoding.EncodeToString(value) }

// serve runs one lock exchange over an accepted WebSocket.
func (g *lockGuest) serve(t *testing.T, writer http.ResponseWriter, request *http.Request, action string) {
	t.Helper()
	socket, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
		Subprotocols: []string{"dr.workspace-lock.v1"},
	})
	if err != nil {
		return
	}
	defer socket.CloseNow()
	ctx := request.Context()

	scheme := hpke.KEM_P256_HKDF_SHA256.Scheme()
	recipientPublic, recipientPrivate, err := scheme.GenerateKeyPair()
	if err != nil {
		t.Error(err)
		return
	}
	recipientBytes, err := recipientPublic.MarshalBinary()
	if err != nil || len(recipientBytes) != 65 || recipientBytes[0] != 4 {
		t.Errorf("the KEM public key is not an uncompressed SEC1 point: %v", err)
		return
	}
	identityBytes := elliptic.Marshal(elliptic.P256(), g.identity.PublicKey.X, g.identity.PublicKey.Y) //nolint:staticcheck

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Error(err)
		return
	}
	g.challenges++
	challengeUUID := fmt.Sprintf("88888888-8888-4888-8888-%012d", g.challenges)
	operationUUID := fmt.Sprintf("99999999-9999-4999-8999-%012d", g.challenges)
	challenge := map[string]any{
		"version":                   int64(1),
		"challenge_uuid":            challengeUUID,
		"organization_uuid":         lockTestOrgUUID,
		"workspace_uuid":            lockTestWorkspace,
		"assignment_generation":     g.generation,
		"boot_uuid":                 lockTestBootUUID,
		"lock_epoch":                int64(1),
		"credential_revision":       int64(1),
		"lease_uuid":                lockTestLease,
		"authority_epoch":           int64(1),
		"operation_uuid":            operationUUID,
		"action":                    action,
		"nonce":                     armor(nonce),
		"expires_at":                g.nowMs + 20000,
		"identity_public_key":       armor(identityBytes),
		"recipient_public_key":      armor(recipientBytes),
		"actor_subject_uuid":        lockTestSubject,
		"membership_uuid":           lockTestMembership,
		"policy_revision":           int64(1),
		"organization_key_revision": int64(1),
		"hold_revision":             int64(0),
		"versions": map[string]any{
			"authorization_version":    int64(1),
			"workspace_access_version": int64(1),
			"placement_generation":     int64(1),
			"assignment_generation":    g.generation,
			"lifecycle_revision":       int64(1),
			"host_generation":          int64(1),
		},
	}
	canonicalChallenge := canonical(challenge)
	digest := sha256.Sum256(append([]byte("dr.workspace-lock.challenge.v1\x00"), canonicalChallenge...))
	r, s, err := ecdsa.Sign(rand.Reader, g.identity, digest[:])
	if err != nil {
		t.Error(err)
		return
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	envelope := canonical(map[string]any{
		"version": int64(1), "challenge": challenge, "signature": armor(signature),
	})
	if err := writeLockEnvelope(ctx, socket, "lock_challenge", envelope); err != nil {
		return
	}

	kind, data, err := socket.Read(ctx)
	if err != nil || kind != websocket.MessageText {
		return
	}
	var frame struct{ Enc, Ciphertext, ChallengeUUID string }
	var raw map[string]any
	if json.Unmarshal(data, &raw) != nil {
		t.Error("the request frame is not JSON")
		return
	}
	frame.Enc, _ = raw["enc"].(string)
	frame.Ciphertext, _ = raw["ciphertext"].(string)
	frame.ChallengeUUID, _ = raw["challenge_uuid"].(string)
	if frame.ChallengeUUID != challengeUUID {
		t.Error("the request frame is not bound to this challenge")
		return
	}
	plaintext, opener := g.open(t, recipientPrivate, frame.Enc, frame.Ciphertext, canonicalChallenge)
	if opener == nil {
		return
	}
	var body map[string]any
	if json.Unmarshal(plaintext, &body) != nil {
		t.Error("the sealed body is not JSON")
		return
	}
	g.lastRequest = body

	result := map[string]any{
		"action": action, "operation_uuid": operationUUID,
		"outcome": "denied", "reason": "lock_attempt_failed",
	}
	if secret, _ := body["secret"].(string); secret == g.pin {
		result = map[string]any{
			"action": action, "operation_uuid": operationUUID, "outcome": "unlocked",
			"device_session_uuid": lockTestSession,
			"expires_at":          g.nowMs + 8*60*60*1000,
		}
	}
	responseAAD := append([]byte(canonicalChallenge), sha256Sum(data)...)
	aead, err := hpke.AEAD_AES128GCM.New(opener.Export([]byte("dr.workspace-lock.response.key.v1"), 16))
	if err != nil {
		t.Error(err)
		return
	}
	sealed := aead.Seal(nil, opener.Export([]byte("dr.workspace-lock.response.nonce.v1"), 12), []byte(canonical(result)), responseAAD)
	response := canonical(map[string]any{
		"version": int64(1), "challenge_uuid": challengeUUID, "ciphertext": armor(sealed),
	})
	if err := writeLockEnvelope(ctx, socket, "lock_response", response); err != nil {
		return
	}
	_ = socket.Close(websocket.StatusNormalClosure, "lock_exchange_complete")
}

func sha256Sum(value []byte) []byte {
	digest := sha256.Sum256(value)
	return digest[:]
}

func (g *lockGuest) open(t *testing.T, private kem.PrivateKey, enc, ciphertext, aad string) ([]byte, hpke.Opener) {
	t.Helper()
	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	receiver, err := suite.NewReceiver(private, []byte("dr.workspace-lock.v1"))
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	encBytes, err := base64.RawURLEncoding.Strict().DecodeString(enc)
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	opener, err := receiver.Setup(encBytes)
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	sealed, err := base64.RawURLEncoding.Strict().DecodeString(ciphertext)
	if err != nil {
		t.Error(err)
		return nil, nil
	}
	plaintext, err := opener.Open(sealed, []byte(aad))
	if err != nil {
		t.Errorf("the guest could not open the client's request: %v", err)
		return nil, nil
	}
	return plaintext, opener
}

func writeLockEnvelope(ctx context.Context, socket *websocket.Conn, kind, frame string) error {
	payload, err := json.Marshal(map[string]string{"type": kind, "frame": frame})
	if err != nil {
		return err
	}
	return socket.Write(ctx, websocket.MessageText, payload)
}

// lockTestServer is a Control Plane that admits exactly what production admits.
func lockTestServer(t *testing.T, guest *lockGuest) *httptest.Server {
	t.Helper()
	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if strings.HasSuffix(request.URL.Path, "/lock") && strings.HasPrefix(request.URL.Path, "/v1/workspaces/") {
			guest.serve(t, writer, request, guest.pendingAction)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		switch {
		case request.URL.Path == "/api/v1" || request.URL.Path == "/api/v1/":
			io.WriteString(writer, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
		case request.URL.Path == "/api/v1/daemons":
			fmt.Fprintf(writer, `{"data":[{"id":%q,"name":"research","status":"running","primary_agent":"codex"}],"meta":{}}`, lockTestWorkspace)
		case request.URL.Path == "/api/v1/tokens/current":
			io.WriteString(writer, `{"data":{"revoked":true},"meta":{}}`)
		case request.URL.Path == "/api/v1/daemons/"+lockTestWorkspace+"/access-tickets":
			var body map[string]any
			json.NewDecoder(request.Body).Decode(&body)
			action, _ := body["action"].(string)
			if body["protocol_version"] != float64(1) {
				writer.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(writer, `{"code":"validation_failed","detail":"protocol_version"}`)
				return
			}
			for key := range body {
				if key != "action" && key != "operation_uuid" && key != "protocol_version" {
					t.Errorf("the lock ticket request carried an unexpected field %q", key)
				}
			}
			if !guest.admittedActions[action] {
				writer.WriteHeader(http.StatusUnprocessableEntity)
				io.WriteString(writer, `{"code":"validation_failed","detail":"action"}`)
				return
			}
			guest.pendingAction = action
			fmt.Fprintf(writer, `{"data":{"ticket":"opaque.lockticket","ticket_version":2,"expires_in":30,"method":"GET","gateway_path":"/v1/workspaces/%s/lock","websocket_protocol":"dr.workspace-lock.v1"},"meta":{}}`, lockTestWorkspace)
		default:
			http.NotFound(writer, request)
		}
	}))
	t.Cleanup(server.Close)
	_ = server
	return server
}

type lockHarness struct {
	server      *httptest.Server
	guest       *lockGuest
	directory   string
	credentials string
	lockPath    string
	output      *bytes.Buffer
	errorOutput *bytes.Buffer
	prompts     []string
	answers     []string
	nowMs       int64
	interactive bool
}

func newLockHarness(t *testing.T) *lockHarness {
	t.Helper()
	nowMs := time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC).UnixMilli()
	guest := newLockGuest(t, nowMs)
	harness := &lockHarness{
		guest: guest, directory: t.TempDir(), output: &bytes.Buffer{},
		errorOutput: &bytes.Buffer{}, nowMs: nowMs, interactive: true,
	}
	harness.server = lockTestServer(t, guest)
	harness.credentials = filepath.Join(harness.directory, "credentials.json")
	harness.lockPath = filepath.Join(harness.directory, "workspace-lock.json")
	document := fmt.Sprintf(`{"version":2,"credentials":{%q:{"token":"dr_cp_token"}}}`, normalizedHost(t, harness.server.URL))
	if err := os.WriteFile(harness.credentials, []byte(document), 0o600); err != nil {
		t.Fatal(err)
	}
	return harness
}

func (h *lockHarness) run(arguments ...string) int {
	h.output.Reset()
	h.errorOutput.Reset()
	h.prompts = nil
	dependencies := Dependencies{
		Output:      h.output,
		ErrorOutput: h.errorOutput,
		Environment: map[string]string{"HOME": h.directory},
		HTTPClient:  h.server.Client(),
		Now:         func() time.Time { return time.UnixMilli(h.nowMs).UTC() },
		Sleep:       func(context.Context, time.Duration) error { return nil },
		IsInteractive: func() bool {
			return h.interactive
		},
		ReadSecret: func(prompt string) (string, error) {
			h.prompts = append(h.prompts, prompt)
			if len(h.answers) == 0 {
				return "", io.EOF
			}
			answer := h.answers[0]
			h.answers = h.answers[1:]
			return answer, nil
		},
	}
	base := []string{"--base-url", h.server.URL, "--credentials-file", h.credentials}
	return Run(context.Background(), append(base, arguments...), dependencies)
}

func (h *lockHarness) storeBytes(t *testing.T) string {
	t.Helper()
	raw, err := os.ReadFile(h.lockPath)
	if err != nil {
		return ""
	}
	return string(raw)
}

// TestWorkspaceUnlockStoresAnExpiringDeviceGrant is the end-to-end happy path
// against a guest that speaks the real protocol.
func TestWorkspaceUnlockStoresAnExpiringDeviceGrant(t *testing.T) {
	harness := newLockHarness(t)
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
		t.Fatalf("unlock exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if secret, _ := harness.guest.lastRequest["secret"].(string); secret != lockTestPIN {
		t.Fatal("the guest did not receive the PIN inside the sealed frame")
	}
	if !strings.Contains(harness.output.String(), "Unlocked research on this device until") {
		t.Fatalf("unexpected output: %s", harness.output.String())
	}
	stored := harness.storeBytes(t)
	if stored == "" {
		t.Fatal("no device grant was stored")
	}
	if strings.Contains(stored, lockTestPIN) || strings.Contains(harness.output.String(), lockTestPIN) ||
		strings.Contains(harness.errorOutput.String(), lockTestPIN) {
		t.Fatal("the PIN reached disk or output")
	}
	if !strings.Contains(stored, harness.guest.identityPin()) {
		t.Fatal("the guest identity pin was not recorded")
	}
	info, err := os.Stat(harness.lockPath)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the lock store must be mode 0600, got %v (%v)", info.Mode().Perm(), err)
	}

	// The grant is readable locally without another exchange, and it carries
	// the eight-hour deadline the guest set.
	if code := harness.run("lock", "status", "research", "--json"); code != 0 {
		t.Fatalf("status exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	var status struct {
		Data struct {
			Device struct {
				Unlocked  bool   `json:"unlocked"`
				ExpiresAt string `json:"expires_at"`
			} `json:"device"`
			Identity struct {
				Pinned       bool   `json:"pinned"`
				Confirmation string `json:"confirmation"`
			} `json:"identity"`
			Guest struct{ State string } `json:"guest"`
		} `json:"data"`
	}
	if err := json.Unmarshal(harness.output.Bytes(), &status); err != nil {
		t.Fatal(err)
	}
	if !status.Data.Device.Unlocked || status.Data.Device.ExpiresAt != "2029-01-01T08:00:00Z" {
		t.Fatalf("unexpected device state: %+v", status.Data.Device)
	}
	if !status.Data.Identity.Pinned || status.Data.Identity.Confirmation != "trusted-provisioning" {
		t.Fatalf("unexpected identity state: %+v", status.Data.Identity)
	}
	// This Control Plane admits no lock.status action, so the guest state is
	// unknown rather than inferred from anything else.
	if status.Data.Guest.State != "unknown" {
		t.Fatalf("guest state must be unknown without a guest report, got %q", status.Data.Guest.State)
	}
}

// TestWorkspaceGrantExpiresOnTheHardDeadline proves there is no sliding
// refresh: the eight-hour deadline drops the grant with no further exchange.
func TestWorkspaceGrantExpiresOnTheHardDeadline(t *testing.T) {
	harness := newLockHarness(t)
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
		t.Fatalf("unlock exit = %d", code)
	}
	harness.nowMs += 8*60*60*1000 - 1000
	if code := harness.run("lock", "status", "research"); code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	if !strings.Contains(harness.output.String(), "unlocked until") {
		t.Fatal("the grant expired before its deadline")
	}
	harness.nowMs += 2000
	if code := harness.run("lock", "status", "research"); code != 0 {
		t.Fatalf("status exit = %d", code)
	}
	if !strings.Contains(harness.output.String(), "This device     locked") {
		t.Fatalf("the grant survived its deadline: %s", harness.output.String())
	}
	if strings.Contains(harness.storeBytes(t), "device_scalar") {
		t.Fatal("an expired device scalar was left on disk")
	}
}

// TestWorkspaceUnlockRefusals covers the paths that must fail closed.
func TestWorkspaceUnlockRefusals(t *testing.T) {
	t.Run("an unpinned guest identity", func(t *testing.T) {
		harness := newLockHarness(t)
		harness.answers = []string{lockTestPIN}
		if code := harness.run("unlock", "research"); code != 5 {
			t.Fatalf("exit = %d, stderr = %s", code, harness.errorOutput.String())
		}
		if !strings.Contains(harness.errorOutput.String(), "lock_identity_unpinned") {
			t.Fatalf("unexpected error: %s", harness.errorOutput.String())
		}
		if harness.storeBytes(t) != "" {
			t.Fatal("an unverified identity was stored")
		}
	})

	t.Run("a changed guest identity", func(t *testing.T) {
		harness := newLockHarness(t)
		harness.answers = []string{lockTestPIN}
		if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
			t.Fatalf("exit = %d", code)
		}
		harness.guest.rotateIdentity(t)
		harness.answers = []string{lockTestPIN}
		if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 5 {
			t.Fatalf("exit = %d, stderr = %s", code, harness.errorOutput.String())
		}
		if !strings.Contains(harness.errorOutput.String(), "lock_identity_changed") {
			t.Fatalf("unexpected error: %s", harness.errorOutput.String())
		}
	})

	t.Run("a wrong PIN", func(t *testing.T) {
		harness := newLockHarness(t)
		harness.answers = []string{"000000"}
		if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 5 {
			t.Fatalf("exit = %d, stderr = %s", code, harness.errorOutput.String())
		}
		if !strings.Contains(harness.errorOutput.String(), "lock_attempt_failed") {
			t.Fatalf("unexpected error: %s", harness.errorOutput.String())
		}
		if strings.Contains(harness.storeBytes(t), "device_scalar") {
			t.Fatal("a refused attempt installed a grant")
		}
	})

	t.Run("a malformed PIN", func(t *testing.T) {
		harness := newLockHarness(t)
		harness.answers = []string{"12345"}
		if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 2 {
			t.Fatalf("exit = %d, stderr = %s", code, harness.errorOutput.String())
		}
		if harness.guest.challenges != 0 {
			t.Fatal("a malformed PIN consumed a guest challenge")
		}
	})

	t.Run("a non-interactive terminal", func(t *testing.T) {
		harness := newLockHarness(t)
		harness.interactive = false
		harness.answers = []string{lockTestPIN}
		if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 2 {
			t.Fatalf("exit = %d, stderr = %s", code, harness.errorOutput.String())
		}
		if !strings.Contains(harness.errorOutput.String(), "tty_required") {
			t.Fatalf("unexpected error: %s", harness.errorOutput.String())
		}
	})

	t.Run("a secret offered on the command line", func(t *testing.T) {
		harness := newLockHarness(t)
		for _, flag := range []string{"--pin", "--secret", "--password", "--phrase"} {
			if code := harness.run("unlock", "research", flag, "482913"); code != 2 {
				t.Fatalf("%s exit = %d", flag, code)
			}
			if strings.Contains(harness.errorOutput.String(), "482913") {
				t.Fatal("a command-line secret was echoed back")
			}
		}
	})
}

// TestWorkspaceLockUnsupportedActionsFailClosed proves the CLI does not degrade
// to another path when the platform does not admit a lock action yet.
func TestWorkspaceLockUnsupportedActionsFailClosed(t *testing.T) {
	harness := newLockHarness(t)
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
		t.Fatalf("unlock exit = %d", code)
	}
	if code := harness.run("lock", "research"); code != 2 {
		t.Fatalf("relock exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if !strings.Contains(harness.errorOutput.String(), "lock_protocol_unsupported") {
		t.Fatalf("unexpected error: %s", harness.errorOutput.String())
	}
	// The local grant is dropped regardless: this device asked to give up its
	// authority and must not keep it because the guest could not be reached.
	if strings.Contains(harness.storeBytes(t), "device_scalar") {
		t.Fatal("a relock left the local device grant in place")
	}

	harness.guest.admittedActions["lock.setup"] = true
	harness.answers = []string{"111111", "111111"}
	// The guest in this harness answers setup like an unlock, which is not a
	// valid rotation result, so the client must refuse rather than believe it.
	if code := harness.run("lock", "setup", "research"); code == 0 {
		t.Fatal("an unrecognised rotation response was accepted")
	}
}

// TestWorkspaceLockPairingRecordsAManualComparison proves the pairing probe
// sends no request frame and records an explicitly compared identity.
func TestWorkspaceLockPairingRecordsAManualComparison(t *testing.T) {
	harness := newLockHarness(t)
	pin := harness.guest.identityPin()
	harness.answers = []string{pin[len(pin)-4:]}
	if code := harness.run("lock", "pair", "research"); code != 0 {
		t.Fatalf("pair exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if harness.guest.lastRequest != nil {
		t.Fatal("the pairing probe sent a request frame")
	}
	if !strings.Contains(harness.storeBytes(t), "manual-comparison") {
		t.Fatalf("the pairing was not recorded: %s", harness.storeBytes(t))
	}
	// A pinned device unlocks without the trust-on-first-use disclosure.
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research"); code != 0 {
		t.Fatalf("unlock exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if strings.Contains(harness.errorOutput.String(), "first use") {
		t.Fatal("a paired device reported a first-use bootstrap")
	}

	// Refusing the comparison stores nothing new and keeps the old pin.
	harness.guest.rotateIdentity(t)
	harness.answers = []string{"zzzz"}
	if code := harness.run("lock", "pair", "research"); code != 5 {
		t.Fatalf("refused pair exit = %d", code)
	}
	if !strings.Contains(harness.storeBytes(t), pin) {
		t.Fatal("a refused comparison replaced the pinned identity")
	}
}

// TestLogoutClearsTheWorkspaceLockStore proves a device grant never outlives
// the session that established it.
func TestLogoutClearsTheWorkspaceLockStore(t *testing.T) {
	harness := newLockHarness(t)
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
		t.Fatalf("unlock exit = %d", code)
	}
	if harness.storeBytes(t) == "" {
		t.Fatal("no grant to clear")
	}
	if code := harness.run("logout"); code != 0 {
		t.Fatalf("logout exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if harness.storeBytes(t) != "" {
		t.Fatalf("logout left workspace lock state behind: %s", harness.storeBytes(t))
	}
}

// TestWorkspaceLockPairForgetRemovesEverything covers the explicit forget path.
func TestWorkspaceLockPairForgetRemovesEverything(t *testing.T) {
	harness := newLockHarness(t)
	harness.answers = []string{lockTestPIN}
	if code := harness.run("unlock", "research", "--trust-on-first-use"); code != 0 {
		t.Fatalf("unlock exit = %d", code)
	}
	if code := harness.run("lock", "pair", "research", "--forget"); code != 0 {
		t.Fatalf("forget exit = %d, stderr = %s", code, harness.errorOutput.String())
	}
	if harness.storeBytes(t) != "" {
		t.Fatal("forget left lock state behind")
	}
}
