package app

import (
	"os"
	"path/filepath"
	"testing"
)

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
