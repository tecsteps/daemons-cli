package credentials

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testOrganization = "33333333-3333-4333-8333-333333333333"
	testWorkspace    = "11111111-1111-4111-8111-111111111111"
	testSession      = "22222222-2222-4222-8222-222222222222"
	testBoot         = "44444444-4444-4444-8444-444444444444"
	testSubject      = "55555555-5555-4555-8555-555555555555"
	testMembership   = "66666666-6666-4666-8666-666666666666"
	testPin          = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	testBase         = "https://daemons.run"
)

func testLockStore(t *testing.T) LockStore {
	t.Helper()
	return LockStore{Path: filepath.Join(t.TempDir(), "workspace-lock.json")}
}

func testScope() LockScope {
	return LockScope{BaseURL: testBase, OrganizationUUID: testOrganization,
		WorkspaceUUID: testWorkspace, AssignmentGeneration: 1}
}

func testGrant(expires int64) LockGrant {
	return LockGrant{
		DeviceSessionUUID: testSession,
		DeviceScalar:      bytes.Repeat([]byte{7}, 32),
		ExpiresAtMs:       expires,
		BootUUID:          testBoot,
		LockEpoch:         1,
		ActorSubjectUUID:  testSubject,
		MembershipUUID:    testMembership,
	}
}

func TestLockStoreKeepsAPinAndAnExpiringGrant(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Pin(testScope(), testPin, LockPinManualComparison); err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(testScope(), testPin, testGrant(now+LockGrantLifetimeMs), now); err != nil {
		t.Fatal(err)
	}
	record, err := store.Read(testBase, testWorkspace, now)
	if err != nil || record.Grant == nil {
		t.Fatalf("the grant was not readable: %v", err)
	}
	if !bytes.Equal(record.Grant.DeviceScalar, bytes.Repeat([]byte{7}, 32)) {
		t.Fatal("the device scalar did not round-trip")
	}
	if record.Confirmation != LockPinManualComparison || !record.Matches(testScope()) {
		t.Fatal("the pin metadata did not round-trip")
	}

	// One millisecond past the deadline the grant is gone, with no renewal.
	if record, err := store.Read(testBase, testWorkspace, now+LockGrantLifetimeMs); err != nil || record.Grant != nil {
		t.Fatalf("the grant outlived its deadline: %v", err)
	}
	// A clock that moved back before the grant was issued cannot revive it.
	if record, err := store.Read(testBase, testWorkspace, now-1); err != nil || record.Grant != nil {
		t.Fatalf("a backwards clock kept the grant alive: %v", err)
	}
}

func TestLockStoreRefusesAnOverlongGrant(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Pin(testScope(), testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(testScope(), testPin, testGrant(now+LockGrantLifetimeMs+1), now); !errors.Is(err, ErrLockStoreInvalid) {
		t.Fatalf("a grant longer than eight hours was accepted: %v", err)
	}
}

func TestLockStoreFailsClosedOnAChangedIdentity(t *testing.T) {
	store := testLockStore(t)
	if err := store.Pin(testScope(), testPin, LockPinManualComparison); err != nil {
		t.Fatal(err)
	}
	other := strings.Repeat("ab", 32)
	if err := store.Pin(testScope(), other, LockPinManualComparison); !errors.Is(err, ErrLockPinChanged) {
		t.Fatalf("a different identity was pinned silently: %v", err)
	}
	changed := testScope()
	changed.AssignmentGeneration = 2
	if err := store.Pin(changed, testPin, LockPinManualComparison); !errors.Is(err, ErrLockPinChanged) {
		t.Fatalf("a new assignment reused the old pin: %v", err)
	}
	// Only an explicit repair replaces it, and it discards the old grant.
	if err := store.Repair(changed, other, LockPinManualComparison); err != nil {
		t.Fatal(err)
	}
	record, err := store.Read(testBase, testWorkspace, 1_700_000_000_000)
	if err != nil || record.IdentityPin != other || record.Grant != nil || record.AssignmentGeneration != 2 {
		t.Fatalf("the repair did not replace the record: %+v %v", record, err)
	}
}

func TestLockStoreGrantRequiresTheMatchingPin(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Grant(testScope(), testPin, testGrant(now+1000), now); !errors.Is(err, ErrLockPinUnknown) {
		t.Fatalf("a grant installed without a pin: %v", err)
	}
	if err := store.Pin(testScope(), testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(testScope(), strings.Repeat("cd", 32), testGrant(now+1000), now); !errors.Is(err, ErrLockPinChanged) {
		t.Fatalf("a grant installed under a different identity: %v", err)
	}
}

func TestLockStoreProtectsItsFile(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Pin(testScope(), testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(store.Path)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("the store must be mode 0600: %v %v", info.Mode().Perm(), err)
	}
	if err := os.Chmod(store.Path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(testBase, testWorkspace, now); err == nil {
		t.Fatal("a world-readable store was accepted")
	}
	if err := os.Chmod(store.Path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Unusable content fails closed rather than being partially believed.
	if err := os.WriteFile(store.Path, []byte(`{"version":1,"workspaces":{"a":{"identity_pin":"nope"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(testBase, testWorkspace, now); !errors.Is(err, ErrLockStoreInvalid) {
		t.Fatalf("a malformed store was accepted: %v", err)
	}
}

func TestLockStoreForgetAndUnpinRemoveEverything(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Pin(testScope(), testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(testScope(), testPin, testGrant(now+1000), now); err != nil {
		t.Fatal(err)
	}
	other := testScope()
	other.BaseURL = "https://staging.example.test"
	if err := store.Pin(other, testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	if err := store.Forget(testBase); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(testBase, testWorkspace, now); !errors.Is(err, ErrLockPinUnknown) {
		t.Fatalf("forget left this host behind: %v", err)
	}
	if _, err := store.Read(other.BaseURL, testWorkspace, now); err != nil {
		t.Fatalf("forget removed another host: %v", err)
	}
	if err := store.Unpin(other.BaseURL, testWorkspace); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(store.Path); err == nil {
		t.Fatal("the empty store file was left on disk")
	}
}

func TestLockStorePruneDropsExpiredScalars(t *testing.T) {
	store := testLockStore(t)
	const now int64 = 1_700_000_000_000
	if err := store.Pin(testScope(), testPin, LockPinTrustedProvisioning); err != nil {
		t.Fatal(err)
	}
	if err := store.Grant(testScope(), testPin, testGrant(now+1000), now); err != nil {
		t.Fatal(err)
	}
	if err := store.Prune(now + 2000); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(store.Path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "device_scalar") {
		t.Fatalf("prune left an expired scalar on disk: %s", raw)
	}
	if !strings.Contains(string(raw), testPin) {
		t.Fatal("prune removed the public identity pin as well")
	}
}
