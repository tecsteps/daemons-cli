package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestUploadRefusesToOverwriteWithoutForce proves the destructive-operation
// consent rule: a colliding name stops the run before any upload is sent, and
// --force is the only way through.
func TestUploadRefusesToOverwriteWithoutForce(t *testing.T) {
	localFile := filepath.Join(t.TempDir(), "note.txt")
	if err := os.WriteFile(localFile, []byte("hello world"), 0o600); err != nil {
		t.Fatal(err)
	}

	t.Run("collision without force sends no upload", func(t *testing.T) {
		fake := &accessWorkspaceServer{listing: `{"data":[{"name":"note.txt","type":"file","size":3,"mtime":1756720000}],"meta":{"next_cursor":null}}`}
		handler, dependencies, output, errorOutput, _ := newAccessWorkspaceServer(t, fake)
		code := Run(context.Background(), []string{"--json", "--host", handler.URL, "upload", recoveryDaemon, localFile}, dependencies)
		if code != 6 {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
		if fake.uploadCount() != 0 {
			t.Fatalf("uploads = %d, want none", fake.uploadCount())
		}
		if !strings.Contains(output.String(), "upload_overwrite_confirmation") {
			t.Fatalf("report = %q", output.String())
		}
		// The refusal must not leave a pending record behind.
		if strings.Contains(strings.Join(fake.actions(), ","), "files.upload") {
			t.Fatalf("actions = %v", fake.actions())
		}
	})

	t.Run("force overwrites and skips the collision read", func(t *testing.T) {
		fake := &accessWorkspaceServer{listing: `{"data":[{"name":"note.txt","type":"file","size":3,"mtime":1756720000}],"meta":{"next_cursor":null}}`}
		handler, dependencies, output, errorOutput, _ := newAccessWorkspaceServer(t, fake)
		code := Run(context.Background(), []string{"--host", handler.URL, "upload", recoveryDaemon, localFile, "--force"}, dependencies)
		if code != 0 {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
		if fake.uploadCount() != 1 {
			t.Fatalf("uploads = %d, want 1", fake.uploadCount())
		}
		for _, action := range fake.actions() {
			if strings.Contains(action, "files.read") {
				t.Fatalf("--force still performed the collision read: %v", fake.actions())
			}
		}
	})
}
