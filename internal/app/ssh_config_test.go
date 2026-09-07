package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRemoveSSHConfigPreservesOtherWorkspace(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"config":       "# daemons-run daemon one\nHost one\n# daemons-run daemon two\nHost two\n",
		"known_hosts":  "dr-one ssh-ed25519 one-key\ndr-two ssh-ed25519 two-key\n",
		"aliases.json": `{"one":"alias-one","two":"alias-two"}`,
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := removeSSHConfig(dir, "one"); err != nil {
		t.Fatal(err)
	}
	for name := range files {
		data, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil || strings.Contains(string(data), "one") || !strings.Contains(string(data), "two") {
			t.Fatalf("other workspace damaged in %s", name)
		}
	}
}

func TestKnownHostReplacementRequiresExplicitVerification(t *testing.T) {
	existing := []byte("dr-workspace ssh-ed25519 old-key\n")
	if err := verifyKnownHost(existing, "workspace", "ssh-ed25519 old-key"); err != nil {
		t.Fatal(err)
	}
	if err := verifyKnownHost(existing, "workspace", "ssh-ed25519 replacement"); err == nil {
		t.Fatal("silently replaced host key")
	}
	if err := verifyKnownHost(existing, "other-workspace", "ssh-ed25519 other-key"); err != nil {
		t.Fatal(err)
	}
}

func TestAtomicPrivateRefusesSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := atomicPrivate(link, []byte("replace")); err == nil {
		t.Fatal("accepted a symlink")
	}
	b, _ := os.ReadFile(target)
	if string(b) != "keep" {
		t.Fatalf("target changed: %q", b)
	}
}
