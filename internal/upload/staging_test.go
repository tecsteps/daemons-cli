package upload

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func stagingFor(t *testing.T) Staging {
	t.Helper()
	credentialsFile := filepath.Join(t.TempDir(), "credentials.json")
	staging, err := OpenStaging(nil, credentialsFile, "11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatal(err)
	}
	return staging
}

func TestStagingRecordsAndResolvesPendingOperations(t *testing.T) {
	staging := stagingFor(t)
	now := time.Date(2026, 9, 8, 10, 0, 0, 0, time.UTC)
	first := Pending{OperationUUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Selector: "uploads/a.txt", Filename: "a.txt", Bytes: 4}
	second := Pending{OperationUUID: "11111111-2222-4333-8444-999999999999", Selector: "uploads/b.txt", Filename: "b.txt", Bytes: 8}
	if err := staging.Add(first, now); err != nil {
		t.Fatal(err)
	}
	if err := staging.Add(second, now); err != nil {
		t.Fatal(err)
	}
	pending, err := staging.List()
	if err != nil || len(pending) != 2 || pending[0].OperationUUID != first.OperationUUID || pending[0].StartedAt != "2026-09-08T10:00:00Z" {
		t.Fatalf("List() = %+v, %v", pending, err)
	}
	info, err := os.Stat(staging.Path())
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("record mode = %v, %v", info, err)
	}
	if err := staging.Remove(first.OperationUUID); err != nil {
		t.Fatal(err)
	}
	pending, err = staging.List()
	if err != nil || len(pending) != 1 || pending[0].OperationUUID != second.OperationUUID {
		t.Fatalf("List() after remove = %+v, %v", pending, err)
	}
	if err := staging.Remove(second.OperationUUID); err != nil {
		t.Fatal(err)
	}
	if pending, err := staging.List(); err != nil || len(pending) != 0 {
		t.Fatalf("List() when empty = %+v, %v", pending, err)
	}
	if _, err := os.Stat(staging.Path()); !os.IsNotExist(err) {
		t.Fatal("empty record was retained")
	}
}

func TestStagingNeverHoldsFileContent(t *testing.T) {
	staging := stagingFor(t)
	if err := staging.Add(Pending{OperationUUID: "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee", Selector: "uploads/a.txt", Filename: "a.txt", Bytes: 4}, time.Now()); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(staging.Path())
	if err != nil {
		t.Fatal(err)
	}
	// Only identity and intent are recorded, so recovery can never replay bytes.
	for _, field := range []string{"content", "contents", "body", "sha256"} {
		if strings.Contains(string(raw), field) {
			t.Fatalf("record carries %q: %s", field, raw)
		}
	}
}

func TestOpenStagingRefusesAnUnsafeDaemonSegment(t *testing.T) {
	credentialsFile := filepath.Join(t.TempDir(), "credentials.json")
	for _, daemonID := range []string{"", "..", "../escape", "a/b", "a\x00b"} {
		if _, err := OpenStaging(nil, credentialsFile, daemonID); err == nil {
			t.Fatalf("OpenStaging(%q) accepted an unsafe segment", daemonID)
		}
	}
}

func TestStagingRejectsACorruptRecordInsteadOfLosingIt(t *testing.T) {
	staging := stagingFor(t)
	if err := os.MkdirAll(filepath.Dir(staging.Path()), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(staging.Path(), []byte(`{"version":99}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := staging.List(); err == nil {
		t.Fatal("List() accepted an unknown record version")
	}
}
