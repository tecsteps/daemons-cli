package app

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAdjacentPublicKeyReadsOnlyPublicSibling(t *testing.T) {
	dir := t.TempDir()
	private := filepath.Join(dir, "id")
	if err := os.WriteFile(private, []byte("private"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(private+".pub", []byte("ssh-ed25519 AAAA test\n"), 0644); err != nil {
		t.Fatal(err)
	}
	got, err := adjacentPublicKey(private)
	if err != nil {
		t.Fatal(err)
	}
	if got != "ssh-ed25519 AAAA test" {
		t.Fatalf("key = %q", got)
	}
}
