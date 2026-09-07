package app

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPayloadCommandRejectsUnsafeInputBeforeNetwork(t *testing.T) {
	root := t.TempDir()
	empty := filepath.Join(root, "empty")
	large := filepath.Join(root, "large")
	link := filepath.Join(root, "link")
	if err := os.WriteFile(empty, nil, 0600); err != nil {
		t.Fatal(err)
	}
	file, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(8*1024*1024 + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()
	if err := os.Symlink(large, link); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{empty, large, link, root, filepath.Join(root, "missing")} {
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, http.DefaultClient, &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", "http://127.0.0.1:1", "payload", "put", "11111111-1111-4111-8111-111111111111", "22222222-2222-4222-8222-222222222222", name}, dependencies)
		if code != 2 || strings.Contains(output.String()+errorOutput.String(), name) {
			t.Fatalf("unsafe payload accepted or path disclosed: %d", code)
		}
	}
}

func TestPayloadCommandsExposeSeparateHelpWithoutAuthentication(t *testing.T) {
	for _, action := range []string{"put", "receipt"} {
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, http.DefaultClient, &output, &errorOutput)
		if code := Run(context.Background(), []string{"payload", action, "--help"}, dependencies); code != 0 || !strings.Contains(output.String(), "payload "+action) {
			t.Fatalf("payload help: %d", code)
		}
	}
}
