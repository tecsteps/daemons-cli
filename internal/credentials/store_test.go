package credentials

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
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
	got, err := store.Load(want.BaseURL)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if got.BaseURL != want.BaseURL || got.Token != want.Token || got.AccountEmail != want.AccountEmail {
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

func TestStoreIsolatesHostsAndDeletesOneAtATime(t *testing.T) {
	store := Store{Path: filepath.Join(t.TempDir(), "credentials.json")}
	production := Credential{BaseURL: "https://daemons.run/api/v1", Token: "dr_cp_production"}
	staging := Credential{BaseURL: "https://staging.example.test/api/v1", Token: "dr_cp_staging"}
	for _, credential := range []Credential{production, staging} {
		if err := store.Save(credential); err != nil {
			t.Fatal(err)
		}
	}
	hosts, err := store.Hosts()
	if err != nil || len(hosts) != 2 || hosts[0] != production.BaseURL || hosts[1] != staging.BaseURL {
		t.Fatalf("Hosts() = %v, %v", hosts, err)
	}
	got, err := store.Load(production.BaseURL)
	if err != nil || got.Token != "dr_cp_production" {
		t.Fatalf("production Load() = %#v, %v", got, err)
	}
	if _, err := store.Load("https://other.example.test/api/v1"); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("unknown host Load() error = %v", err)
	}

	if err := store.Delete(staging.BaseURL); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Load(staging.BaseURL); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("deleted host Load() error = %v", err)
	}
	if _, err := store.Load(production.BaseURL); err != nil {
		t.Fatalf("production survived Delete() = %v", err)
	}
	if err := store.Delete(production.BaseURL); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(store.Path); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("empty store should remove the file, got %v", err)
	}
}

func TestStoreMigratesVersionOneFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	legacy := `{"version":1,"base_url":"https://daemons.run/api/v1","token":"dr_cp_legacy","account_email":"developer@example.test","expires_at":"2030-01-01T00:00:00Z"}`
	if err := os.WriteFile(path, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	store := Store{Path: path}
	got, err := store.Load("https://daemons.run/api/v1")
	if err != nil || got.Token != "dr_cp_legacy" || got.AccountEmail != "developer@example.test" || got.ExpiresAt != "2030-01-01T00:00:00Z" {
		t.Fatalf("legacy Load() = %#v, %v", got, err)
	}

	if err := store.Save(Credential{BaseURL: "https://staging.example.test/api/v1", Token: "dr_cp_staging"}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `"version":2`) || !strings.Contains(string(data), "dr_cp_legacy") || !strings.Contains(string(data), "dr_cp_staging") || strings.Contains(string(data), `"base_url"`) {
		t.Fatalf("migrated file = %s", data)
	}
	if got, err := store.Load("https://daemons.run/api/v1"); err != nil || got.Token != "dr_cp_legacy" {
		t.Fatalf("legacy entry lost after migration: %#v, %v", got, err)
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

	_, err := (Store{Path: path}).Load("https://example.test/api/v1")
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

	_, err := (Store{Path: link}).Load("https://example.test/api/v1")
	if err == nil {
		t.Fatal("Load() succeeded for a symlink")
	}
}

func TestDeleteMissingCredentialIsIdempotent(t *testing.T) {
	err := (Store{Path: filepath.Join(t.TempDir(), "missing")}).Delete("https://daemons.run/api/v1")
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Delete() error = %v", err)
	}
}
