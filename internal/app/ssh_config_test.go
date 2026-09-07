package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestSSHConfigWritesDNSOnlyHostKeepaliveAndProxyCommand(t *testing.T) {
	daemon := "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-Daemons-Api-Version", "v1")
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/daemons/"+daemon+"/ssh" {
			http.NotFound(w, r)
			return
		}
		io.WriteString(w, `{"data":{"enabled":true,"reconciled":true,"host_key":"ssh-ed25519 AAAA","host_key_fingerprint":"SHA256:x","keys":[]},"meta":{}}`)
	}))
	defer server.Close()

	home := t.TempDir()
	identity := filepath.Join(home, "id_ed25519")
	if err := os.WriteFile(identity, []byte("unused"), 0600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	var errorOutput bytes.Buffer
	code := Run(context.Background(), []string{"--host", server.URL, "ssh-config", daemon, "--identity", identity}, Dependencies{
		Output:      &output,
		ErrorOutput: &errorOutput,
		Environment: map[string]string{"HOME": home, "DAEMONS_TOKEN": "dr_cp_ssh"},
		HTTPClient:  server.Client(),
	})
	if code != 0 {
		t.Fatalf("exit %d stdout %q stderr %q", code, output.String(), errorOutput.String())
	}
	matches, err := filepath.Glob(filepath.Join(home, ".ssh", "daemons-run", "*", "config"))
	if err != nil || len(matches) != 1 {
		t.Fatalf("managed config %v %v", matches, err)
	}
	body, err := os.ReadFile(matches[0])
	if err != nil {
		t.Fatal(err)
	}
	config := string(body)
	for _, want := range []string{
		"HostName ssh.daemons.run",
		"Port 2222",
		"ProxyCommand",
		"ssh-proxy " + daemon,
		"ServerAliveInterval 30",
		"ServerAliveCountMax 3",
		"HostKeyAlias dr-" + daemon,
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q in %q", want, config)
		}
	}
	if strings.Contains(config, "HostName ignored") {
		t.Fatal("still writing ignored hostname")
	}
}
