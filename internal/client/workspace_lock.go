package client

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/cloudflare/circl/hpke"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

// The E22 workspace lock protocol as the guest speaks it. Every byte on this
// wire is RFC 8785 canonical JSON, the guest challenge is verified against a
// previously established identity pin before any secret is encrypted, and the
// request is sealed with HPKE base mode DHKEM(P-256, HKDF-SHA256) /
// HKDF-SHA256 / AES-128-GCM (suite 0x0010/0x0001/0x0001).
//
// This file deliberately contains no persistence, no terminal input and no
// command wiring: a bug here must not be reachable by a path that skipped
// verification. See internal/credentials/workspace_lock.go for the device
// cache and internal/app/workspace_lock.go for the commands.

const (
	// LockProtocolLabel is the HPKE info string and the WebSocket subprotocol.
	LockProtocolLabel = "dr.workspace-lock.v1"
	// LockChallengeDomain prefixes the guest's challenge signature input.
	LockChallengeDomain = "dr.workspace-lock.challenge.v1"
	// LockDeviceDomain prefixes a device proof signature input.
	LockDeviceDomain = "dr.workspace-lock.device.v1"

	lockResponseKeyLabel   = "dr.workspace-lock.response.key.v1"
	lockResponseNonceLabel = "dr.workspace-lock.response.nonce.v1"

	// LockFrameLimit is the pre-parse cap on every protocol frame.
	LockFrameLimit = 16384
	// LockEnvelopeLimit bounds the {type,frame} envelope carrying a frame.
	LockEnvelopeLimit = 32768
	// LockChallengeLifetime is the guest's hard challenge deadline.
	LockChallengeLifetimeMs int64 = 30000
	// LockGrantLifetimeMs is the eight-hour device grant deadline. There is no
	// sliding refresh: a grant is never extended, only replaced by a new unlock.
	LockGrantLifetimeMs int64 = 8 * 60 * 60 * 1000
)

var (
	lockUUIDPattern   = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	lockActionPattern = regexp.MustCompile(`^[a-z][a-z0-9_.]{0,95}$`)
	lockBase64URL     = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)
	lockPinPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lockSecretPattern = regexp.MustCompile(`^(?:[0-9]{4}|[0-9]{6})$`)
	lockPhrasePattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	lockBase64Pattern = regexp.MustCompile(`^[A-Za-z0-9_-]+$`)

	lockIdentifierFields = []string{
		"challenge_uuid", "organization_uuid", "workspace_uuid", "boot_uuid",
		"lease_uuid", "operation_uuid", "actor_subject_uuid", "membership_uuid",
	}
	lockRevisionFields = []string{
		"lock_epoch", "credential_revision", "authority_epoch",
		"policy_revision", "organization_key_revision", "hold_revision",
	}
	lockVersionFields = []string{
		"authorization_version", "workspace_access_version", "placement_generation",
		"assignment_generation", "lifecycle_revision", "host_generation",
	}
)

// LockDenied is the single bounded outcome this package reports. Detailed
// authentication outcomes stay inside the encrypted response; nothing here
// distinguishes a wrong PIN from a forged challenge to a network observer or
// to a log file.
func LockDenied() error {
	return errs.New("lock_unavailable", "The workspace lock exchange could not be completed.", 5)
}

func lockDeniedAs(code, message string, exit int) error {
	return errs.New(code, message, exit)
}

// ---------------------------------------------------------------------------
// RFC 8785 canonical JSON over the closed ASCII-field lock schemas.
// ---------------------------------------------------------------------------

// canonicalLockJSON serialises the closed protocol schemas. Arrays never occur
// in them and are refused rather than guessed at.
func canonicalLockJSON(value any) (string, error) {
	var builder strings.Builder
	if err := writeCanonicalLockJSON(&builder, value); err != nil {
		return "", err
	}
	return builder.String(), nil
}

func writeCanonicalLockJSON(builder *strings.Builder, value any) error {
	switch typed := value.(type) {
	case nil:
		builder.WriteString("null")
	case bool:
		builder.WriteString(strconv.FormatBool(typed))
	case string:
		writeCanonicalLockString(builder, typed)
	case int:
		return writeCanonicalLockInteger(builder, int64(typed))
	case int64:
		return writeCanonicalLockInteger(builder, typed)
	case json.Number:
		number, err := typed.Int64()
		if err != nil {
			return LockDenied()
		}
		return writeCanonicalLockInteger(builder, number)
	case map[string]any:
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		builder.WriteByte('{')
		for index, key := range keys {
			if index > 0 {
				builder.WriteByte(',')
			}
			writeCanonicalLockString(builder, key)
			builder.WriteByte(':')
			if err := writeCanonicalLockJSON(builder, typed[key]); err != nil {
				return err
			}
		}
		builder.WriteByte('}')
	default:
		return LockDenied()
	}
	return nil
}

func writeCanonicalLockInteger(builder *strings.Builder, value int64) error {
	if value > maximumSafeInteger || value < -maximumSafeInteger {
		return LockDenied()
	}
	builder.WriteString(strconv.FormatInt(value, 10))
	return nil
}

// writeCanonicalLockString implements RFC 8785 section 3.2.2.2 escaping. It is
// written out rather than delegated to encoding/json so that a non-ASCII
// organization password round-trips byte for byte with the browser's
// JSON.stringify, which escapes neither HTML characters nor U+2028/U+2029.
func writeCanonicalLockString(builder *strings.Builder, value string) {
	const hexDigits = "0123456789abcdef"
	builder.WriteByte('"')
	for _, point := range value {
		switch point {
		case '"':
			builder.WriteString(`\"`)
		case '\\':
			builder.WriteString(`\\`)
		case '\b':
			builder.WriteString(`\b`)
		case '\f':
			builder.WriteString(`\f`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		default:
			if point < 0x20 {
				builder.WriteString(`\u00`)
				builder.WriteByte(hexDigits[(point>>4)&15])
				builder.WriteByte(hexDigits[point&15])
				continue
			}
			// Invalid UTF-8 and unpaired surrogates already decoded to the
			// replacement character before reaching here. Re-emitting it makes
			// the canonical round-trip differ from the sender's bytes, which is
			// how strict UTF-8 is enforced: such a frame is refused.
			builder.WriteRune(point)
		}
	}
	builder.WriteByte('"')
}

// parseCanonicalLockJSON decodes strict UTF-8 JSON and requires the value to
// re-serialise to exactly the input bytes. That single equality rejects
// duplicate keys, unsorted keys, whitespace, noncanonical numbers and a BOM
// before any field is interpreted.
func parseCanonicalLockJSON(text string, limit int) (map[string]any, error) {
	if len(text) == 0 || len(text) > limit {
		return nil, LockDenied()
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return nil, LockDenied()
	}
	if decoder.More() {
		return nil, LockDenied()
	}
	object, ok := value.(map[string]any)
	if !ok {
		return nil, LockDenied()
	}
	canonical, err := canonicalLockJSON(object)
	if err != nil || canonical != text {
		return nil, LockDenied()
	}
	return object, nil
}

func lockExactKeys(value map[string]any, keys ...string) bool {
	if len(value) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func lockString(value map[string]any, key string) (string, bool) {
	text, ok := value[key].(string)
	return text, ok
}

func lockInteger(value map[string]any, key string) (int64, bool) {
	number, ok := value[key].(json.Number)
	if !ok {
		return 0, false
	}
	parsed, err := number.Int64()
	if err != nil || parsed > maximumSafeInteger || parsed < -maximumSafeInteger {
		return 0, false
	}
	return parsed, true
}

// lockArmor is unpadded base64url, the only binary encoding on this wire.
func lockArmor(value []byte) string {
	return base64.RawURLEncoding.EncodeToString(value)
}

func lockUnarmor(value string, length int) ([]byte, error) {
	if !lockBase64Pattern.MatchString(value) {
		return nil, LockDenied()
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(value)
	if err != nil || (length > 0 && len(decoded) != length) || lockArmor(decoded) != value {
		return nil, LockDenied()
	}
	return decoded, nil
}

// ---------------------------------------------------------------------------
// The signed guest challenge.
// ---------------------------------------------------------------------------

// LockChallenge is the verified guest challenge. Its Canonical field is the
// exact bytes the guest signed and the exact AAD for the sealed request.
type LockChallenge struct {
	Canonical string

	ChallengeUUID    string
	OrganizationUUID string
	WorkspaceUUID    string
	BootUUID         string
	LeaseUUID        string
	OperationUUID    string
	ActorSubjectUUID string
	MembershipUUID   string
	ResourceUUID     string

	AssignmentGeneration    int64
	LockEpoch               int64
	CredentialRevision      int64
	AuthorityEpoch          int64
	PolicyRevision          int64
	OrganizationKeyRevision int64
	HoldRevision            int64

	Action    string
	ExpiresAt int64

	IdentityPublicKey  string
	RecipientPublicKey string

	identityBytes  []byte
	recipientBytes []byte
}

// IdentityPin is the SHA-256 of the raw 65-byte SEC1 identity public key, in
// lowercase hex. It is public material: it is the value a client pins.
func (c LockChallenge) IdentityPin() string {
	digest := sha256.Sum256(c.identityBytes)
	return lockHex(digest[:])
}

func lockHex(value []byte) string {
	const hexDigits = "0123456789abcdef"
	out := make([]byte, 0, len(value)*2)
	for _, b := range value {
		out = append(out, hexDigits[b>>4], hexDigits[b&15])
	}
	return string(out)
}

// LockScope is what the caller already believes about this workspace. Every
// field present is compared to the challenge before the pin is even consulted.
type LockScope struct {
	OrganizationUUID     string
	WorkspaceUUID        string
	AssignmentGeneration int64
	Action               string
	ResourceUUID         string
}

// ParseLockChallenge validates the signed envelope's shape without trusting
// its contents. The signature is checked by VerifyLockChallenge.
func ParseLockChallenge(text string) (LockChallenge, []byte, error) {
	var challenge LockChallenge
	envelope, err := parseCanonicalLockJSON(text, LockFrameLimit)
	if err != nil {
		return challenge, nil, err
	}
	if !lockExactKeys(envelope, "challenge", "signature", "version") {
		return challenge, nil, LockDenied()
	}
	if version, ok := lockInteger(envelope, "version"); !ok || version != 1 {
		return challenge, nil, LockDenied()
	}
	signatureText, ok := lockString(envelope, "signature")
	if !ok {
		return challenge, nil, LockDenied()
	}
	signature, err := lockUnarmor(signatureText, 64)
	if err != nil {
		return challenge, nil, err
	}
	body, ok := envelope["challenge"].(map[string]any)
	if !ok {
		return challenge, nil, LockDenied()
	}

	action, ok := lockString(body, "action")
	if !ok || !lockActionPattern.MatchString(action) {
		return challenge, nil, LockDenied()
	}
	// A working-transport challenge names the resource it authorises; a lock
	// management challenge must not carry one.
	working := !strings.HasPrefix(action, "lock.")
	expected := append([]string{}, lockIdentifierFields...)
	expected = append(expected, lockRevisionFields...)
	expected = append(expected, "version", "assignment_generation", "versions",
		"action", "nonce", "expires_at", "identity_public_key", "recipient_public_key")
	if working {
		expected = append(expected, "resource_uuid")
	}
	if !lockExactKeys(body, expected...) {
		return challenge, nil, LockDenied()
	}
	if version, ok := lockInteger(body, "version"); !ok || version != 1 {
		return challenge, nil, LockDenied()
	}
	for _, field := range lockIdentifierFields {
		value, ok := lockString(body, field)
		if !ok || !lockUUIDPattern.MatchString(value) {
			return challenge, nil, LockDenied()
		}
	}
	for _, field := range lockRevisionFields {
		value, ok := lockInteger(body, field)
		if !ok || value < 0 {
			return challenge, nil, LockDenied()
		}
	}
	generation, ok := lockInteger(body, "assignment_generation")
	if !ok || generation < 1 {
		return challenge, nil, LockDenied()
	}
	expires, ok := lockInteger(body, "expires_at")
	if !ok || expires < 0 {
		return challenge, nil, LockDenied()
	}
	versions, ok := body["versions"].(map[string]any)
	if !ok || !lockExactKeys(versions, lockVersionFields...) {
		return challenge, nil, LockDenied()
	}
	for _, field := range lockVersionFields {
		value, ok := lockInteger(versions, field)
		if !ok || value < 1 {
			return challenge, nil, LockDenied()
		}
	}
	if fenced, _ := lockInteger(versions, "assignment_generation"); fenced != generation {
		return challenge, nil, LockDenied()
	}
	nonce, ok := lockString(body, "nonce")
	if !ok {
		return challenge, nil, LockDenied()
	}
	if _, err := lockUnarmor(nonce, 32); err != nil {
		return challenge, nil, err
	}
	if working {
		resource, ok := lockString(body, "resource_uuid")
		if !ok || !lockUUIDPattern.MatchString(resource) {
			return challenge, nil, LockDenied()
		}
		challenge.ResourceUUID = resource
	}

	identityText, _ := lockString(body, "identity_public_key")
	recipientText, _ := lockString(body, "recipient_public_key")
	identityBytes, err := lockSEC1(identityText)
	if err != nil {
		return challenge, nil, err
	}
	recipientBytes, err := lockSEC1(recipientText)
	if err != nil {
		return challenge, nil, err
	}
	// The identity signing key and the per-challenge HPKE recipient key are
	// distinct by construction; a guest reusing one for both is refused.
	if identityText == recipientText {
		return challenge, nil, LockDenied()
	}

	canonical, err := canonicalLockJSON(body)
	if err != nil {
		return challenge, nil, err
	}

	challenge.Canonical = canonical
	challenge.ChallengeUUID, _ = lockString(body, "challenge_uuid")
	challenge.OrganizationUUID, _ = lockString(body, "organization_uuid")
	challenge.WorkspaceUUID, _ = lockString(body, "workspace_uuid")
	challenge.BootUUID, _ = lockString(body, "boot_uuid")
	challenge.LeaseUUID, _ = lockString(body, "lease_uuid")
	challenge.OperationUUID, _ = lockString(body, "operation_uuid")
	challenge.ActorSubjectUUID, _ = lockString(body, "actor_subject_uuid")
	challenge.MembershipUUID, _ = lockString(body, "membership_uuid")
	challenge.AssignmentGeneration = generation
	challenge.LockEpoch, _ = lockInteger(body, "lock_epoch")
	challenge.CredentialRevision, _ = lockInteger(body, "credential_revision")
	challenge.AuthorityEpoch, _ = lockInteger(body, "authority_epoch")
	challenge.PolicyRevision, _ = lockInteger(body, "policy_revision")
	challenge.OrganizationKeyRevision, _ = lockInteger(body, "organization_key_revision")
	challenge.HoldRevision, _ = lockInteger(body, "hold_revision")
	challenge.Action = action
	challenge.ExpiresAt = expires
	challenge.IdentityPublicKey = identityText
	challenge.RecipientPublicKey = recipientText
	challenge.identityBytes = identityBytes
	challenge.recipientBytes = recipientBytes
	return challenge, signature, nil
}

// lockSEC1 accepts only an uncompressed, on-curve, non-infinite P-256 point.
// Compressed points and DER structures are refused rather than converted.
func lockSEC1(value string) ([]byte, error) {
	raw, err := lockUnarmor(value, 65)
	if err != nil {
		return nil, err
	}
	if raw[0] != 4 {
		return nil, LockDenied()
	}
	if _, err := ecdh.P256().NewPublicKey(raw); err != nil {
		return nil, LockDenied()
	}
	return raw, nil
}

// VerifyLockChallengeOptions carries what the caller must already know. No
// implicit pairing happens here: an empty IdentityPin is refused, and the
// caller decides separately whether a first, disclosed bootstrap is allowed.
type VerifyLockChallengeOptions struct {
	IdentityPin string
	Scope       LockScope
	NowMs       int64
}

// VerifyLockChallenge proves the challenge came from the pinned guest and
// binds every authority field the caller already knows before any secret is
// prepared for it.
func VerifyLockChallenge(text string, options VerifyLockChallengeOptions) (LockChallenge, error) {
	challenge, signature, err := ParseLockChallenge(text)
	if err != nil {
		return LockChallenge{}, err
	}
	scope := options.Scope
	if !lockPinPattern.MatchString(options.IdentityPin) ||
		challenge.Action != scope.Action ||
		challenge.ResourceUUID != scope.ResourceUUID {
		return LockChallenge{}, LockDenied()
	}
	if scope.OrganizationUUID != "" && challenge.OrganizationUUID != scope.OrganizationUUID {
		return LockChallenge{}, LockDenied()
	}
	if scope.WorkspaceUUID != "" && challenge.WorkspaceUUID != scope.WorkspaceUUID {
		return LockChallenge{}, LockDenied()
	}
	if scope.AssignmentGeneration != 0 && challenge.AssignmentGeneration != scope.AssignmentGeneration {
		return LockChallenge{}, LockDenied()
	}
	now := options.NowMs
	if now <= 0 || challenge.ExpiresAt <= now || challenge.ExpiresAt > now+LockChallengeLifetimeMs {
		return LockChallenge{}, LockDenied()
	}
	// A changed pin fails closed. It is never silently re-accepted.
	if challenge.IdentityPin() != options.IdentityPin {
		return LockChallenge{}, lockDeniedAs("lock_identity_changed",
			"The workspace guest identity changed. Pair this device again before unlocking.", 5)
	}
	public, err := lockECDSAPublicKey(challenge.identityBytes)
	if err != nil {
		return LockChallenge{}, err
	}
	// High-S and low-S are both accepted: replay identity is the challenge
	// UUID the guest consumes once, never the signature bytes.
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	digest := sha256.Sum256(lockSigningInput(LockChallengeDomain, challenge.Canonical))
	if !ecdsa.Verify(public, digest[:], r, s) {
		return LockChallenge{}, LockDenied()
	}
	return challenge, nil
}

func lockSigningInput(domain, canonical string) []byte {
	input := make([]byte, 0, len(domain)+1+len(canonical))
	input = append(input, domain...)
	input = append(input, 0)
	input = append(input, canonical...)
	return input
}

func lockECDSAPublicKey(raw []byte) (*ecdsa.PublicKey, error) {
	if len(raw) != 65 || raw[0] != 4 {
		return nil, LockDenied()
	}
	x := new(big.Int).SetBytes(raw[1:33])
	y := new(big.Int).SetBytes(raw[33:])
	public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}
	if !public.Curve.IsOnCurve(x, y) {
		return nil, LockDenied()
	}
	return public, nil
}

// ---------------------------------------------------------------------------
// The client device key.
// ---------------------------------------------------------------------------

// LockDeviceKey is a client-held P-256 signing key. It is the device: a cookie,
// a hostname or a user agent is not.
type LockDeviceKey struct {
	private *ecdsa.PrivateKey
}

// NewLockDeviceKey generates a fresh device key from the system CSPRNG.
func NewLockDeviceKey() (LockDeviceKey, error) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return LockDeviceKey{}, LockDenied()
	}
	return LockDeviceKey{private: private}, nil
}

// LockDeviceKeyFromScalar rebuilds a stored device key. The scalar is the only
// private value the CLI persists, and only for the grant's lifetime.
func LockDeviceKeyFromScalar(scalar []byte) (LockDeviceKey, error) {
	if len(scalar) != 32 {
		return LockDeviceKey{}, LockDenied()
	}
	d := new(big.Int).SetBytes(scalar)
	order := elliptic.P256().Params().N
	if d.Sign() == 0 || d.Cmp(order) >= 0 {
		return LockDeviceKey{}, LockDenied()
	}
	private := &ecdsa.PrivateKey{D: d}
	private.PublicKey.Curve = elliptic.P256()
	private.PublicKey.X, private.PublicKey.Y = elliptic.P256().ScalarBaseMult(scalar)
	return LockDeviceKey{private: private}, nil
}

// Scalar returns the private scalar for the device cache. Callers must not log
// it, print it or send it anywhere.
func (k LockDeviceKey) Scalar() []byte {
	if k.private == nil {
		return nil
	}
	scalar := make([]byte, 32)
	k.private.D.FillBytes(scalar)
	return scalar
}

// PublicKey is the uncompressed SEC1 point, unpadded base64url.
func (k LockDeviceKey) PublicKey() string {
	if k.private == nil {
		return ""
	}
	return lockArmor(elliptic.Marshal(elliptic.P256(), k.private.PublicKey.X, k.private.PublicKey.Y)) //nolint:staticcheck // SEC1 uncompressed is the wire format.
}

// Valid reports whether this key can sign.
func (k LockDeviceKey) Valid() bool { return k.private != nil }

func (k LockDeviceKey) sign(domain, canonical string) (string, error) {
	if k.private == nil {
		return "", LockDenied()
	}
	digest := sha256.Sum256(lockSigningInput(domain, canonical))
	r, s, err := ecdsa.Sign(rand.Reader, k.private, digest[:])
	if err != nil {
		return "", LockDenied()
	}
	signature := make([]byte, 64)
	r.FillBytes(signature[:32])
	s.FillBytes(signature[32:])
	return lockArmor(signature), nil
}

// ---------------------------------------------------------------------------
// The sealed request and its single response.
// ---------------------------------------------------------------------------

// LockExchange is one sealed request and the exactly-one response it may open.
type LockExchange struct {
	Challenge LockChallenge
	Frame     string

	responseKey   []byte
	responseNonce []byte
	requestDigest [32]byte
	consumed      bool
}

// SealLockRequest encrypts one request to the verified guest. body carries the
// action-specific fields; operation_uuid, action and device_public_key are
// supplied here so a caller cannot accidentally unbind them from the challenge.
func SealLockRequest(challenge LockChallenge, device LockDeviceKey, body map[string]any) (*LockExchange, error) {
	if !device.Valid() || challenge.Canonical == "" {
		return nil, LockDenied()
	}
	plaintext := map[string]any{
		"operation_uuid":    challenge.OperationUUID,
		"action":            challenge.Action,
		"device_public_key": device.PublicKey(),
	}
	for key, value := range body {
		if _, taken := plaintext[key]; taken {
			return nil, LockDenied()
		}
		plaintext[key] = value
	}
	encoded, err := canonicalLockJSON(plaintext)
	if err != nil {
		return nil, err
	}

	suite := hpke.NewSuite(hpke.KEM_P256_HKDF_SHA256, hpke.KDF_HKDF_SHA256, hpke.AEAD_AES128GCM)
	recipient, err := hpke.KEM_P256_HKDF_SHA256.Scheme().UnmarshalBinaryPublicKey(challenge.recipientBytes)
	if err != nil {
		return nil, LockDenied()
	}
	sender, err := suite.NewSender(recipient, []byte(LockProtocolLabel))
	if err != nil {
		return nil, LockDenied()
	}
	enc, sealer, err := sender.Setup(rand.Reader)
	if err != nil {
		return nil, LockDenied()
	}
	// Exactly one seal at sequence zero. The exporter keys are taken before the
	// context is dropped; there is no second use of this context.
	ciphertext, err := sealer.Seal([]byte(encoded), []byte(challenge.Canonical))
	if err != nil {
		return nil, LockDenied()
	}
	exchange := &LockExchange{
		Challenge:     challenge,
		responseKey:   sealer.Export([]byte(lockResponseKeyLabel), 16),
		responseNonce: sealer.Export([]byte(lockResponseNonceLabel), 12),
	}
	frame, err := canonicalLockJSON(map[string]any{
		"version":        int64(1),
		"challenge_uuid": challenge.ChallengeUUID,
		"enc":            lockArmor(enc),
		"ciphertext":     lockArmor(ciphertext),
	})
	if err != nil {
		return nil, err
	}
	if len(frame) > LockFrameLimit {
		return nil, LockDenied()
	}
	exchange.Frame = frame
	exchange.requestDigest = sha256.Sum256([]byte(frame))
	return exchange, nil
}

// Open decrypts the guest's single response. A second call is refused: the
// AEAD nonce is used exactly once and a duplicate reply is never opened.
func (e *LockExchange) Open(text string) (map[string]any, error) {
	if e == nil || e.consumed {
		return nil, LockDenied()
	}
	e.consumed = true
	outer, err := parseCanonicalLockJSON(text, LockFrameLimit)
	if err != nil {
		return nil, err
	}
	if !lockExactKeys(outer, "version", "challenge_uuid", "ciphertext") {
		return nil, LockDenied()
	}
	if version, ok := lockInteger(outer, "version"); !ok || version != 1 {
		return nil, LockDenied()
	}
	if id, ok := lockString(outer, "challenge_uuid"); !ok || id != e.Challenge.ChallengeUUID {
		return nil, LockDenied()
	}
	armored, ok := lockString(outer, "ciphertext")
	if !ok {
		return nil, LockDenied()
	}
	ciphertext, err := lockUnarmor(armored, 0)
	if err != nil || len(ciphertext) <= 16 {
		return nil, LockDenied()
	}

	aead, err := hpke.AEAD_AES128GCM.New(e.responseKey)
	if err != nil {
		return nil, LockDenied()
	}
	aad := make([]byte, 0, len(e.Challenge.Canonical)+32)
	aad = append(aad, e.Challenge.Canonical...)
	aad = append(aad, e.requestDigest[:]...)
	plaintext, err := aead.Open(nil, e.responseNonce, ciphertext, aad)
	lockZero(e.responseKey)
	lockZero(e.responseNonce)
	if err != nil {
		return nil, LockDenied()
	}
	defer lockZero(plaintext)

	result, err := parseCanonicalLockJSON(string(plaintext), LockFrameLimit)
	if err != nil {
		return nil, err
	}
	if action, ok := lockString(result, "action"); !ok || action != e.Challenge.Action {
		return nil, LockDenied()
	}
	if operation, ok := lockString(result, "operation_uuid"); !ok || operation != e.Challenge.OperationUUID {
		return nil, LockDenied()
	}
	if _, ok := lockString(result, "outcome"); !ok {
		return nil, LockDenied()
	}
	return result, nil
}

func lockZero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

// ---------------------------------------------------------------------------
// Action bodies the CLI is allowed to send.
// ---------------------------------------------------------------------------

// LockSecret is a PIN held only in memory. It is never written to disk, never
// placed in a flag or environment variable and never echoed.
type LockSecret string

// Valid reports whether the secret matches the frozen four-or-six ASCII digit
// policy, including leading zeroes. No trimming, padding or Unicode digit
// conversion happens anywhere in this package.
func (s LockSecret) Valid() bool { return lockSecretPattern.MatchString(string(s)) }

// LockRecoveryPhrase is the 64 hex character engineer phrase. Hyphens and
// ASCII spaces are removed on entry; every other malformed input is refused.
type LockRecoveryPhrase string

// NormalizeLockRecoveryPhrase strips the display grouping only.
func NormalizeLockRecoveryPhrase(value string) (LockRecoveryPhrase, error) {
	stripped := strings.Map(func(point rune) rune {
		if point == '-' || point == ' ' {
			return -1
		}
		return point
	}, value)
	if !lockPhrasePattern.MatchString(stripped) {
		return "", lockDeniedAs("usage_error", "A recovery phrase is 64 hexadecimal characters.", 2)
	}
	return LockRecoveryPhrase(stripped), nil
}

// LockUnlockBody is the encrypted body of lock.unlock.
func LockUnlockBody(secret LockSecret) (map[string]any, error) {
	if !secret.Valid() {
		return nil, lockDeniedAs("usage_error", "A PIN is exactly four or six digits.", 2)
	}
	return map[string]any{"credential_type": "pin", "secret": string(secret)}, nil
}

// LockSetupBody begins enrollment. The guest generates the recovery phrase; the
// client never chooses or transports it.
func LockSetupBody(secret LockSecret) (map[string]any, error) {
	body, err := LockUnlockBody(secret)
	if err != nil {
		return nil, err
	}
	body["step"] = "begin"
	return body, nil
}

// LockChangeBody rotates the PIN. Both factors travel inside one sealed frame.
func LockChangeBody(current, next LockSecret) (map[string]any, error) {
	if !current.Valid() || !next.Valid() {
		return nil, lockDeniedAs("usage_error", "A PIN is exactly four or six digits.", 2)
	}
	return map[string]any{
		"step": "begin", "credential_type": "pin",
		"secret": string(current), "new_credential_type": "pin", "new_secret": string(next),
	}, nil
}

// LockRecoverBody consumes the engineer recovery phrase and stages a new PIN.
func LockRecoverBody(phrase LockRecoveryPhrase, next LockSecret) (map[string]any, error) {
	if !next.Valid() {
		return nil, lockDeniedAs("usage_error", "A PIN is exactly four or six digits.", 2)
	}
	if !lockPhrasePattern.MatchString(string(phrase)) {
		return nil, lockDeniedAs("usage_error", "A recovery phrase is 64 hexadecimal characters.", 2)
	}
	return map[string]any{
		"step": "begin", "recovery_phrase": string(phrase),
		"new_credential_type": "pin", "new_secret": string(next),
	}, nil
}

// LockConfirmBody proves the client saved the phrase the guest displayed once.
func LockConfirmBody(setupUUID, nonce string, phrase LockRecoveryPhrase) (map[string]any, error) {
	if !lockUUIDPattern.MatchString(setupUUID) || !lockPhrasePattern.MatchString(string(phrase)) {
		return nil, LockDenied()
	}
	if _, err := lockUnarmor(nonce, 32); err != nil {
		return nil, err
	}
	return map[string]any{
		"step": "confirm", "setup_uuid": setupUUID,
		"confirmation_nonce": nonce, "recovery_phrase": string(phrase),
	}, nil
}

// LockStatusBody asks for enrollment and lock state. It carries no secret; the
// device signature inside the sealed frame is the only authority it presents.
func LockStatusBody(device LockDeviceKey, sessionUUID string, challenge LockChallenge) (map[string]any, error) {
	proof, err := SignLockDeviceProof(device, sessionUUID, challenge)
	if err != nil {
		return nil, err
	}
	return map[string]any{"device_proof": proof}, nil
}

// LockLockBody relocks. Either a live device signature or a fresh PIN is
// accepted; the guest decides which it requires.
func LockLockBody(device LockDeviceKey, sessionUUID string, challenge LockChallenge, secret LockSecret) (map[string]any, error) {
	if sessionUUID != "" {
		return LockStatusBody(device, sessionUUID, challenge)
	}
	return LockUnlockBody(secret)
}

// ---------------------------------------------------------------------------
// Device proof for working transports.
// ---------------------------------------------------------------------------

// LockDeviceProof is exactly the three fields the guest accepts. Nothing else
// travels: no device public key a guest could be tricked into adopting.
type LockDeviceProof struct {
	ChallengeUUID     string `json:"challenge_uuid"`
	DeviceSessionUUID string `json:"device_session_uuid"`
	Signature         string `json:"signature"`
}

// SignLockDeviceProof signs an already verified challenge with the device key.
func SignLockDeviceProof(device LockDeviceKey, sessionUUID string, challenge LockChallenge) (map[string]any, error) {
	if !device.Valid() || !lockUUIDPattern.MatchString(sessionUUID) || challenge.Canonical == "" {
		return nil, LockDenied()
	}
	signature, err := device.sign(LockDeviceDomain, challenge.Canonical)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"challenge_uuid":      challenge.ChallengeUUID,
		"device_session_uuid": sessionUUID,
		"signature":           signature,
	}, nil
}

// ---------------------------------------------------------------------------
// The guest's unlock result.
// ---------------------------------------------------------------------------

// LockUnlockResult is the bounded outcome of lock.unlock.
type LockUnlockResult struct {
	Outcome           string
	DeviceSessionUUID string
	ExpiresAtMs       int64
	Reason            string
}

// ReadLockUnlockResult validates the guest's response shape and its expiry
// bound. An eight-hour deadline is a maximum, never a renewal.
func ReadLockUnlockResult(result map[string]any, nowMs int64) (LockUnlockResult, error) {
	outcome, ok := lockString(result, "outcome")
	if !ok {
		return LockUnlockResult{}, LockDenied()
	}
	if outcome != "unlocked" {
		if !lockExactKeys(result, "action", "operation_uuid", "outcome", "reason") {
			return LockUnlockResult{}, LockDenied()
		}
		reason, ok := lockString(result, "reason")
		if !ok {
			return LockUnlockResult{}, LockDenied()
		}
		return LockUnlockResult{Outcome: outcome, Reason: reason}, lockOutcomeError(reason)
	}
	if !lockExactKeys(result, "action", "operation_uuid", "outcome", "device_session_uuid", "expires_at") {
		return LockUnlockResult{}, LockDenied()
	}
	session, ok := lockString(result, "device_session_uuid")
	if !ok || !lockUUIDPattern.MatchString(session) {
		return LockUnlockResult{}, LockDenied()
	}
	expires, ok := lockInteger(result, "expires_at")
	if !ok || expires <= nowMs || expires > nowMs+LockGrantLifetimeMs {
		return LockUnlockResult{}, LockDenied()
	}
	return LockUnlockResult{Outcome: outcome, DeviceSessionUUID: session, ExpiresAtMs: expires}, nil
}

// lockOutcomeError maps the guest's closed reason enum onto the CLI's bounded
// errors. An unknown reason stays generic rather than being echoed to a user.
func lockOutcomeError(reason string) error {
	switch reason {
	case "lock_attempt_failed", "lock_denied":
		return lockDeniedAs("lock_attempt_failed", "That PIN was not accepted.", 5)
	case "lock_rate_limited":
		return lockDeniedAs("lock_rate_limited", "Too many failed attempts. The workspace is in a cooldown.", 7)
	case "lock_setup_required":
		return lockDeniedAs("lock_setup_required", "This workspace has no lock credential yet. Run daemons lock setup.", 5)
	case "lock_session_expired":
		return lockDeniedAs("lock_session_expired", "The device session expired. Unlock again.", 5)
	case "lock_protocol_unsupported":
		return lockDeniedAs("lock_protocol_unsupported", "The workspace guest requires a newer CLI. Upgrade daemons.", 2)
	case "handoff_required":
		return lockDeniedAs("handoff_required", "This operation needs an explicit handoff approval.", 5)
	}
	return LockDenied()
}

// NewLockOperationID mints the operation identity that binds a lock exchange
// end to end: the ticket, the signed challenge, the sealed body and the
// response all carry it, and a rotation's confirm step reuses it.
func NewLockOperationID() string { return newAccessOperationID() }

// LockRotationResult is the guest's pending setup, change or recover step. The
// phrase is guest-generated and is displayed exactly once.
type LockRotationResult struct {
	SetupUUID         string
	ConfirmationNonce string
	Phrase            LockRecoveryPhrase
}

// ReadLockRotationResult validates the pending rotation the guest staged. It
// deliberately requires the exact field set: a response that carried anything
// else is refused rather than partially believed.
func ReadLockRotationResult(result map[string]any) (LockRotationResult, error) {
	if !lockExactKeys(result, "action", "operation_uuid", "outcome", "setup_uuid", "confirmation_nonce", "recovery_phrase") {
		outcome, _ := lockString(result, "outcome")
		if outcome != "" && outcome != "pending" {
			if reason, ok := lockString(result, "reason"); ok {
				return LockRotationResult{}, lockOutcomeError(reason)
			}
		}
		return LockRotationResult{}, LockDenied()
	}
	if outcome, ok := lockString(result, "outcome"); !ok || outcome != "pending" {
		return LockRotationResult{}, LockDenied()
	}
	setup, ok := lockString(result, "setup_uuid")
	if !ok || !lockUUIDPattern.MatchString(setup) {
		return LockRotationResult{}, LockDenied()
	}
	nonce, ok := lockString(result, "confirmation_nonce")
	if !ok {
		return LockRotationResult{}, LockDenied()
	}
	if _, err := lockUnarmor(nonce, 32); err != nil {
		return LockRotationResult{}, err
	}
	phrase, ok := lockString(result, "recovery_phrase")
	if !ok || !lockPhrasePattern.MatchString(phrase) {
		return LockRotationResult{}, LockDenied()
	}
	return LockRotationResult{SetupUUID: setup, ConfirmationNonce: nonce, Phrase: LockRecoveryPhrase(phrase)}, nil
}

// GroupLockRecoveryPhrase renders the phrase in the contract's sixteen groups
// of four. It is display formatting only; the stored and compared value is the
// bare 64 hex characters.
func GroupLockRecoveryPhrase(phrase LockRecoveryPhrase) string {
	value := string(phrase)
	if len(value) != 64 {
		return ""
	}
	groups := make([]string, 0, 16)
	for index := 0; index < 64; index += 4 {
		groups = append(groups, value[index:index+4])
	}
	return strings.Join(groups, "-")
}

// ReadLockStatusResult reduces the guest's status reply to the bounded fields
// the CLI may show. It never surfaces a verifier, a hash, a phrase or another
// device's identifiers, and an unrecognised shape reports unknown rather than
// guessing.
func ReadLockStatusResult(result map[string]any) map[string]any {
	status := map[string]any{"state": "unknown", "reason": "lock_status_unavailable"}
	state, ok := lockString(result, "state")
	if !ok || (state != "locked" && state != "unlocked") {
		return status
	}
	status = map[string]any{"state": state}
	if enrolled, ok := result["enrolled"].(bool); ok {
		status["enrolled"] = enrolled
	}
	if expires, ok := lockInteger(result, "device_expires_at"); ok && expires > 0 {
		status["device_expires_at"] = expires
	}
	return status
}

// ---------------------------------------------------------------------------
// Device authority on working transports.
// ---------------------------------------------------------------------------

// LockDeviceAuthority is a live grant a working transport may prove with. It is
// built from the stored grant, never from a challenge: a guest cannot supply
// the device key it will be compared against.
type LockDeviceAuthority struct {
	Device               LockDeviceKey
	SessionUUID          string
	IdentityPin          string
	OrganizationUUID     string
	WorkspaceUUID        string
	BootUUID             string
	ActorSubjectUUID     string
	MembershipUUID       string
	AssignmentGeneration int64
	LockEpoch            int64
	CredentialRevision   int64
	ExpiresAtMs          int64
}

// Scope describes what this authority may be asked to prove for one action.
func (a LockDeviceAuthority) Scope(action, resourceUUID string) LockScope {
	return LockScope{
		OrganizationUUID:     a.OrganizationUUID,
		WorkspaceUUID:        a.WorkspaceUUID,
		AssignmentGeneration: a.AssignmentGeneration,
		Action:               action,
		ResourceUUID:         resourceUUID,
	}
}

// Live reports whether the eight-hour deadline still holds. It is checked again
// immediately before every signature, not only when the grant is loaded.
func (a LockDeviceAuthority) Live(nowMs int64) bool {
	return a.Device.Valid() && lockUUIDPattern.MatchString(a.SessionUUID) &&
		nowMs > 0 && a.ExpiresAtMs > nowMs && a.ExpiresAtMs <= nowMs+LockGrantLifetimeMs
}

// Prove verifies a working-transport challenge against this grant and returns
// the exactly-three-field proof. Every authority field the guest signed must
// equal the one the grant was issued under: a new boot, a new lock epoch, a
// changed credential revision or a different assignment all fail closed.
func (a LockDeviceAuthority) Prove(frame, action, resourceUUID string, nowMs int64) (map[string]any, error) {
	if !a.Live(nowMs) {
		return nil, lockDeniedAs("lock_session_expired", "The device session expired. Unlock again.", 5)
	}
	challenge, err := VerifyLockChallenge(frame, VerifyLockChallengeOptions{
		IdentityPin: a.IdentityPin,
		Scope:       a.Scope(action, resourceUUID),
		NowMs:       nowMs,
	})
	if err != nil {
		return nil, err
	}
	if challenge.BootUUID != a.BootUUID || challenge.LockEpoch != a.LockEpoch ||
		challenge.CredentialRevision != a.CredentialRevision ||
		challenge.ActorSubjectUUID != a.ActorSubjectUUID ||
		challenge.MembershipUUID != a.MembershipUUID {
		return nil, lockDeniedAs("lock_session_expired",
			"The workspace guest moved on from this device session. Unlock again.", 5)
	}
	return SignLockDeviceProof(a.Device, a.SessionUUID, challenge)
}

// RespondToLockDeviceChallenge turns the gateway's lock_device_challenge
// envelope into the lock_device_proof envelope a working transport sends back.
// The proof carries no device public key: the guest compares the signature
// against the key it already holds for this session.
func (a LockDeviceAuthority) RespondToLockDeviceChallenge(envelopeText, action, resourceUUID string, nowMs int64) (string, error) {
	if len(envelopeText) > LockEnvelopeLimit {
		return "", LockDenied()
	}
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(envelopeText))
	if err := decoder.Decode(&envelope); err != nil || decoder.More() || len(envelope) != 2 {
		return "", LockDenied()
	}
	var kind, frame string
	if err := json.Unmarshal(envelope["type"], &kind); err != nil || kind != "lock_device_challenge" {
		return "", LockDenied()
	}
	if err := json.Unmarshal(envelope["frame"], &frame); err != nil || frame == "" || len(frame) > LockFrameLimit {
		return "", LockDenied()
	}
	proof, err := a.Prove(frame, action, resourceUUID, nowMs)
	if err != nil {
		return "", err
	}
	reply, err := json.Marshal(map[string]any{"type": "lock_device_proof", "proof": proof})
	if err != nil {
		return "", LockDenied()
	}
	return string(reply), nil
}

// LockHandoffBody approves a reassignment with the engineer's own factor. Every
// scope field comes from the Control Plane's view of the operation that exists,
// never from the user, so the guest and the client bind the same reassignment.
func LockHandoffBody(secret LockSecret, phrase string, scope *LockHandoffScope, challenge LockChallenge) (map[string]any, error) {
	body, err := lockEngineerFactor(secret, phrase)
	if err != nil {
		return nil, err
	}
	if scope == nil || !scope.PreserveData {
		return nil, lockDeniedAs("lock_handoff_unavailable",
			"There is no reassignment waiting for this workspace to be handed over.", 5)
	}
	var successor any
	if scope.SuccessorMembershipUUID != nil {
		successor = *scope.SuccessorMembershipUUID
	}
	if scope.OldAssignmentGeneration != challenge.AssignmentGeneration {
		return nil, lockDeniedAs("lock_handoff_scope_denied",
			"The reassignment moved on. Read the pending handoff again before approving it.", 5)
	}
	body["handoff_scope"] = map[string]any{
		// The identity comes from the guest's own verified challenge, never from the
		// Control Plane view, so a substituted workspace cannot be approved here.
		"organization_uuid":         challenge.OrganizationUUID,
		"workspace_uuid":            challenge.WorkspaceUUID,
		"operation_uuid":            scope.OperationUUID,
		"successor_membership_uuid": successor,
		"old_assignment_generation": scope.OldAssignmentGeneration,
		"new_assignment_generation": scope.NewAssignmentGeneration,
		"old_placement_generation":  scope.OldPlacementGeneration,
		"new_placement_generation":  scope.NewPlacementGeneration,
		"preserve_data":             true,
	}
	return body, nil
}

// LockReplacementBody authorizes the Owner's pending organization key
// replacement. The rotation identity comes from the Control Plane and the
// confirmation code from the Owner directly, so both parties must agree before
// the guest accepts the engineer's factor.
func LockReplacementBody(secret LockSecret, phrase, confirmationNonce string, pending *LockReplacementPending) (map[string]any, error) {
	body, err := lockEngineerFactor(secret, phrase)
	if err != nil {
		return nil, err
	}
	if pending == nil {
		return nil, lockDeniedAs("lock_replacement_unavailable",
			"There is no organization key replacement waiting for this workspace.", 5)
	}
	if len(confirmationNonce) != 43 || !lockBase64URL.MatchString(confirmationNonce) {
		return nil, lockDeniedAs("usage_error",
			"The confirmation code is the 43 character value the Owner read out.", 2)
	}
	body["rotation_uuid"] = pending.RotationUUID
	body["confirmation_nonce"] = confirmationNonce
	body["expected_key_revision"] = pending.ExpectedKeyRevision
	body["new_key_revision"] = pending.NewKeyRevision
	return body, nil
}

// lockEngineerFactor accepts exactly one factor: a PIN or a recovery phrase,
// never both and never neither.
func lockEngineerFactor(secret LockSecret, phrase string) (map[string]any, error) {
	if (secret == "") == (phrase == "") {
		return nil, lockDeniedAs("usage_error", "Enter either the workspace PIN or the recovery phrase.", 2)
	}
	if phrase != "" {
		return map[string]any{"credential_type": "recovery_phrase", "secret": phrase}, nil
	}
	if !secret.Valid() {
		return nil, lockDeniedAs("usage_error", "A PIN is exactly four or six digits.", 2)
	}
	return map[string]any{"credential_type": "pin", "secret": string(secret)}, nil
}

// ReadLockDecisionResult validates a decision response before the caller reports
// anything. A sealed refusal is a refusal: `denied` never reads as success, and an
// outcome the guest did not name is treated as one.
func ReadLockDecisionResult(result map[string]any, action string) error {
	outcome, ok := lockString(result, "outcome")
	if !ok {
		return LockDenied()
	}
	if outcome == "applied" || (action == "lock.organization.rotate" && outcome == "pending") {
		return nil
	}
	if !lockExactKeys(result, "action", "operation_uuid", "outcome", "reason") {
		return LockDenied()
	}
	reason, ok := lockString(result, "reason")
	if !ok {
		return LockDenied()
	}
	return lockOutcomeError(reason)
}
