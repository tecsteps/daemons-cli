package credentials

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestStoreRoundTripUsesOwnerOnlyPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "credentials.json")
	store := Store{Path: path}
	want := Credential{
		BaseURL:      "https://daemons.run/api/v1",
		Token:        "dr_cp_secret",
		AccountEmail: "developer@example.test",
	}

	if err := store.Save(want); err != nil {
		t.Fatalf("Save() error = %v", err)
	}
	got, err := store.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.Version != 1 || got.BaseURL != want.BaseURL || got.Token != want.Token || got.AccountEmail != want.AccountEmail {
		t.Fatalf("Load() = %#v", got)
	}

	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0o600 {
			t.Fatalf("credentials mode = %o, want 600", info.Mode().Perm())
		}
		directoryInfo, err := os.Stat(filepath.Dir(path))
		if err != nil {
			t.Fatal(err)
		}
		if directoryInfo.Mode().Perm() != 0o700 {
			t.Fatalf("directory mode = %o, want 700", directoryInfo.Mode().Perm())
		}
	}
}

func TestStoreRejectsLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission test")
	}

	path := filepath.Join(t.TempDir(), "credentials.json")
	if err := os.WriteFile(path, []byte(`{"version":1,"base_url":"https://example.test/api/v1","token":"dr_cp_secret"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	_, err := (Store{Path: path}).Load()
	if err == nil {
		t.Fatal("Load() succeeded for a mode-0644 file")
	}
}

func TestStoreRejectsSymlinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink privileges vary on Windows")
	}

	directory := t.TempDir()
	target := filepath.Join(directory, "target")
	link := filepath.Join(directory, "credentials.json")
	if err := os.WriteFile(target, []byte(`{"version":1,"base_url":"https://example.test/api/v1","token":"dr_cp_secret"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := (Store{Path: link}).Load()
	if err == nil {
		t.Fatal("Load() succeeded for a symlink")
	}
}

func TestDeleteMissingCredentialIsIdempotent(t *testing.T) {
	err := (Store{Path: filepath.Join(t.TempDir(), "missing")}).Delete()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete() error = %v", err)
	}
}
