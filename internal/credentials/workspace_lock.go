package credentials

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
)

// The workspace lock device store. It is deliberately separate from the
// Control Plane token store: a lock device grant is not an API credential, it
// expires on a hard eight-hour deadline, and it must be removable without
// touching a login.
//
// What is stored: the public guest identity pin, and, while a grant is live,
// the device signing scalar with its session UUID and the guest authority the
// grant is bound to. What is never stored: a PIN, a recovery phrase, an
// organization password, or any value derived from one.

const (
	// LockGrantLifetimeMs is the contract's hard eight-hour device deadline.
	// There is no sliding refresh and no remember-device setting.
	LockGrantLifetimeMs int64 = 8 * 60 * 60 * 1000

	lockStoreVersion = 1
)

var (
	lockUUIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	lockPinPattern  = regexp.MustCompile(`^[0-9a-f]{64}$`)

	// ErrLockPinChanged reports a guest identity that differs from the pinned
	// one. It is never resolved automatically: the user re-pairs explicitly.
	ErrLockPinChanged = errors.New("workspace guest identity changed")
	// ErrLockPinUnknown reports that this device has never pinned this guest.
	ErrLockPinUnknown = errors.New("workspace guest identity is not pinned")
	// ErrLockStoreInvalid reports unusable on-disk state. It fails closed.
	ErrLockStoreInvalid = errors.New("workspace lock store is invalid")
)

// LockPinConfirmation records how the pin was established, so the CLI can be
// honest about a trust-on-first-use bootstrap rather than calling it verified.
type LockPinConfirmation string

const (
	// LockPinTrustedProvisioning is a first, disclosed bootstrap.
	LockPinTrustedProvisioning LockPinConfirmation = "trusted-provisioning"
	// LockPinManualComparison is a pin the user compared against a trusted
	// device and accepted.
	LockPinManualComparison LockPinConfirmation = "manual-comparison"
)

func (c LockPinConfirmation) valid() bool {
	return c == LockPinTrustedProvisioning || c == LockPinManualComparison
}

// LockScope names one workspace assignment on one Control Plane. A grant never
// crosses any of these four boundaries.
type LockScope struct {
	BaseURL              string
	OrganizationUUID     string
	WorkspaceUUID        string
	AssignmentGeneration int64
}

func (s LockScope) valid() bool {
	return s.BaseURL != "" && !strings.ContainsAny(s.BaseURL, "\x00\n\r") &&
		lockUUIDPattern.MatchString(s.OrganizationUUID) &&
		lockUUIDPattern.MatchString(s.WorkspaceUUID) &&
		s.AssignmentGeneration >= 1
}

// key locates a record by the two identifiers a client knows before it has
// verified anything: the Control Plane it is talking to and the workspace it
// named. The organization and assignment generation live inside the record and
// are compared to the guest's challenge, so a change in either fails closed
// instead of silently pinning a different assignment.
func (s LockScope) key() string {
	return lockKey(s.BaseURL, s.WorkspaceUUID)
}

func lockKey(baseURL, workspaceUUID string) string {
	return baseURL + "|" + workspaceUUID
}

// LockGrant is a live device session. DeviceScalar is the only private value
// the CLI writes to disk, and only until the grant's deadline.
type LockGrant struct {
	DeviceSessionUUID  string `json:"device_session_uuid"`
	DeviceScalar       []byte `json:"-"`
	EncodedScalar      string `json:"device_scalar"`
	IssuedAtMs         int64  `json:"issued_at"`
	ExpiresAtMs        int64  `json:"expires_at"`
	BootUUID           string `json:"boot_uuid"`
	LockEpoch          int64  `json:"lock_epoch"`
	CredentialRevision int64  `json:"credential_revision"`
	ActorSubjectUUID   string `json:"actor_subject_uuid"`
	MembershipUUID     string `json:"membership_uuid"`
}

// LockRecord is one workspace assignment's client state.
type LockRecord struct {
	OrganizationUUID     string              `json:"organization_uuid"`
	AssignmentGeneration int64               `json:"assignment_generation"`
	IdentityPin          string              `json:"identity_pin"`
	Confirmation         LockPinConfirmation `json:"confirmation"`
	Grant                *LockGrant          `json:"grant,omitempty"`
}

// Matches reports whether this record was pinned for the same organization and
// assignment the guest is now presenting.
func (r LockRecord) Matches(scope LockScope) bool {
	return r.OrganizationUUID == scope.OrganizationUUID &&
		r.AssignmentGeneration == scope.AssignmentGeneration
}

type lockFile struct {
	Version    int                   `json:"version"`
	Workspaces map[string]LockRecord `json:"workspaces"`
}

// LockStore is the owner-only JSON file backend for lock device state.
type LockStore struct {
	Path string
}

// DefaultLockPath places the lock store beside the credentials file, so one
// configuration directory holds everything a logout must clear.
func DefaultLockPath(environment map[string]string) (string, error) {
	if configured := environment["DAEMONS_WORKSPACE_LOCK_FILE"]; configured != "" {
		return configured, nil
	}
	credentials, err := DefaultPath(environment)
	if err != nil {
		return "", err
	}
	return filepath.Join(filepath.Dir(credentials), "workspace-lock.json"), nil
}

func (s LockStore) read() (lockFile, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return lockFile{Version: lockStoreVersion, Workspaces: map[string]LockRecord{}}, nil
		}
		return lockFile{}, fmt.Errorf("inspect workspace lock store: %w", err)
	}
	if err := validateLockFile(s.Path, info); err != nil {
		return lockFile{}, err
	}
	data, err := os.ReadFile(s.Path)
	if err != nil {
		return lockFile{}, fmt.Errorf("read workspace lock store: %w", err)
	}
	var document lockFile
	if err := json.Unmarshal(data, &document); err != nil {
		return lockFile{}, ErrLockStoreInvalid
	}
	if document.Version != lockStoreVersion {
		return lockFile{}, ErrLockStoreInvalid
	}
	if document.Workspaces == nil {
		document.Workspaces = map[string]LockRecord{}
	}
	for key, record := range document.Workspaces {
		if !lockPinPattern.MatchString(record.IdentityPin) || !record.Confirmation.valid() ||
			!lockUUIDPattern.MatchString(record.OrganizationUUID) || record.AssignmentGeneration < 1 {
			return lockFile{}, ErrLockStoreInvalid
		}
		if record.Grant == nil {
			continue
		}
		scalar, err := base64.RawStdEncoding.Strict().DecodeString(record.Grant.EncodedScalar)
		if err != nil || len(scalar) != 32 || !lockUUIDPattern.MatchString(record.Grant.DeviceSessionUUID) ||
			!lockUUIDPattern.MatchString(record.Grant.BootUUID) ||
			!lockUUIDPattern.MatchString(record.Grant.ActorSubjectUUID) ||
			!lockUUIDPattern.MatchString(record.Grant.MembershipUUID) ||
			record.Grant.LockEpoch < 0 || record.Grant.CredentialRevision < 0 ||
			record.Grant.IssuedAtMs <= 0 || record.Grant.ExpiresAtMs <= record.Grant.IssuedAtMs ||
			record.Grant.ExpiresAtMs-record.Grant.IssuedAtMs > LockGrantLifetimeMs {
			// A malformed or over-long grant is dropped, never trusted.
			record.Grant = nil
			document.Workspaces[key] = record
			continue
		}
		record.Grant.DeviceScalar = scalar
		document.Workspaces[key] = record
	}
	return document, nil
}

// Read returns this workspace assignment's pinned identity and its live grant,
// if any. Expired grants, and grants issued in the future because the clock
// moved backwards, are dropped before the record is returned.
func (s LockStore) Read(baseURL, workspaceUUID string, nowMs int64) (LockRecord, error) {
	if baseURL == "" || !lockUUIDPattern.MatchString(workspaceUUID) {
		return LockRecord{}, ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		return LockRecord{}, err
	}
	record, ok := document.Workspaces[lockKey(baseURL, workspaceUUID)]
	if !ok {
		return LockRecord{}, ErrLockPinUnknown
	}
	if record.Grant != nil && !lockGrantLive(*record.Grant, nowMs) {
		record.Grant = nil
	}
	return record, nil
}

// lockGrantLive is deliberately conservative about time. A wall clock that
// moved backwards past the grant's issue time cannot be used to keep it alive.
func lockGrantLive(grant LockGrant, nowMs int64) bool {
	return nowMs > 0 && nowMs >= grant.IssuedAtMs && nowMs < grant.ExpiresAtMs &&
		grant.ExpiresAtMs-grant.IssuedAtMs <= LockGrantLifetimeMs
}

// Pin records the guest identity for this assignment. An existing pin is never
// silently replaced: a different one fails closed and requires explicit
// re-pairing, which also discards any grant held under the old identity.
func (s LockStore) Pin(scope LockScope, pin string, confirmation LockPinConfirmation) error {
	if !scope.valid() || !lockPinPattern.MatchString(pin) || !confirmation.valid() {
		return ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		return err
	}
	key := scope.key()
	if existing, ok := document.Workspaces[key]; ok {
		if existing.IdentityPin != pin || !existing.Matches(scope) {
			return ErrLockPinChanged
		}
		return nil
	}
	document.Workspaces[key] = LockRecord{
		OrganizationUUID:     scope.OrganizationUUID,
		AssignmentGeneration: scope.AssignmentGeneration,
		IdentityPin:          pin,
		Confirmation:         confirmation,
	}
	return s.write(document)
}

// Repair replaces the pinned identity after the user explicitly accepted a new
// one. Every grant under the old identity is discarded.
func (s LockStore) Repair(scope LockScope, pin string, confirmation LockPinConfirmation) error {
	if !scope.valid() || !lockPinPattern.MatchString(pin) || !confirmation.valid() {
		return ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		return err
	}
	document.Workspaces[scope.key()] = LockRecord{
		OrganizationUUID:     scope.OrganizationUUID,
		AssignmentGeneration: scope.AssignmentGeneration,
		IdentityPin:          pin,
		Confirmation:         confirmation,
	}
	return s.write(document)
}

// Grant installs a device session under an already pinned identity. It refuses
// a grant whose deadline exceeds the contract's eight hours.
func (s LockStore) Grant(scope LockScope, pin string, grant LockGrant, nowMs int64) error {
	if !scope.valid() || !lockPinPattern.MatchString(pin) || len(grant.DeviceScalar) != 32 ||
		!lockUUIDPattern.MatchString(grant.DeviceSessionUUID) ||
		!lockUUIDPattern.MatchString(grant.BootUUID) ||
		!lockUUIDPattern.MatchString(grant.ActorSubjectUUID) ||
		!lockUUIDPattern.MatchString(grant.MembershipUUID) ||
		grant.LockEpoch < 0 || grant.CredentialRevision < 0 ||
		nowMs <= 0 || grant.ExpiresAtMs <= nowMs || grant.ExpiresAtMs > nowMs+LockGrantLifetimeMs {
		return ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		return err
	}
	key := scope.key()
	existing, ok := document.Workspaces[key]
	if !ok {
		return ErrLockPinUnknown
	}
	if existing.IdentityPin != pin || !existing.Matches(scope) {
		return ErrLockPinChanged
	}
	grant.IssuedAtMs = nowMs
	grant.EncodedScalar = base64.RawStdEncoding.EncodeToString(grant.DeviceScalar)
	existing.Grant = &grant
	document.Workspaces[key] = existing
	return s.write(document)
}

// Revoke drops one workspace's grant, keeping its pin. Locking, stopping or
// reassigning the workspace all reach this path.
func (s LockStore) Revoke(baseURL, workspaceUUID string) error {
	if baseURL == "" || !lockUUIDPattern.MatchString(workspaceUUID) {
		return ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		return err
	}
	key := lockKey(baseURL, workspaceUUID)
	record, ok := document.Workspaces[key]
	if !ok || record.Grant == nil {
		return nil
	}
	record.Grant = nil
	document.Workspaces[key] = record
	return s.write(document)
}

// Forget removes every record for one Control Plane, pins included. Logout
// calls it: a device grant must not outlive the session that established it.
func (s LockStore) Forget(baseURL string) error {
	document, err := s.read()
	if err != nil {
		if errors.Is(err, ErrLockStoreInvalid) {
			// Unusable state is removed rather than left behind on logout.
			return s.remove()
		}
		return err
	}
	prefix := baseURL + "|"
	changed := false
	for key := range document.Workspaces {
		if strings.HasPrefix(key, prefix) {
			delete(document.Workspaces, key)
			changed = true
		}
	}
	if !changed {
		return nil
	}
	if len(document.Workspaces) == 0 {
		return s.remove()
	}
	return s.write(document)
}

// Prune removes grants that already expired. It runs on every command that
// touches the store, so a stale scalar is not left on disk indefinitely.
func (s LockStore) Prune(nowMs int64) error {
	document, err := s.read()
	if err != nil {
		if errors.Is(err, ErrLockStoreInvalid) {
			return s.remove()
		}
		return err
	}
	changed := false
	for key, record := range document.Workspaces {
		if record.Grant != nil && !lockGrantLive(*record.Grant, nowMs) {
			record.Grant = nil
			document.Workspaces[key] = record
			changed = true
		}
	}
	if !changed {
		return nil
	}
	return s.write(document)
}

// Scopes lists the stored keys, sorted. It is used by status output and never
// exposes a scalar.
func (s LockStore) Scopes() ([]string, error) {
	document, err := s.read()
	if err != nil {
		return nil, err
	}
	keys := make([]string, 0, len(document.Workspaces))
	for key := range document.Workspaces {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys, nil
}

func (s LockStore) remove() error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove workspace lock store: %w", err)
	}
	return nil
}

func (s LockStore) write(document lockFile) error {
	document.Version = lockStoreVersion
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create workspace lock directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect workspace lock directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("workspace lock directory must be a directory, not a symlink")
	}
	if err := validateOwner(directoryInfo); err != nil {
		return fmt.Errorf("workspace lock directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect workspace lock directory: %w", err)
	}
	if info, err := os.Lstat(s.Path); err == nil {
		if err := validateLockFile(s.Path, info); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect workspace lock store: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".workspace-lock-*")
	if err != nil {
		return fmt.Errorf("create temporary workspace lock store: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary workspace lock store: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		temporary.Close()
		return fmt.Errorf("encode workspace lock store: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync workspace lock store: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close workspace lock store: %w", err)
	}
	if err := os.Rename(temporaryPath, s.Path); err != nil {
		return fmt.Errorf("replace workspace lock store: %w", err)
	}
	return os.Chmod(s.Path, 0o600)
}

func validateLockFile(path string, info fs.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("workspace lock store %s must be a regular file, not a symlink", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("workspace lock store %s must have mode 0600", path)
	}
	if err := validateOwner(info); err != nil {
		return fmt.Errorf("workspace lock store %s: %w", path, err)
	}
	return nil
}

// Unpin removes one workspace's record entirely, pin and grant together. It is
// the explicit "forget this guest" path; a changed identity is never resolved
// by silently overwriting.
func (s LockStore) Unpin(baseURL, workspaceUUID string) error {
	if baseURL == "" || !lockUUIDPattern.MatchString(workspaceUUID) {
		return ErrLockStoreInvalid
	}
	document, err := s.read()
	if err != nil {
		if errors.Is(err, ErrLockStoreInvalid) {
			return s.remove()
		}
		return err
	}
	key := lockKey(baseURL, workspaceUUID)
	if _, ok := document.Workspaces[key]; !ok {
		return nil
	}
	delete(document.Workspaces, key)
	if len(document.Workspaces) == 0 {
		return s.remove()
	}
	return s.write(document)
}
