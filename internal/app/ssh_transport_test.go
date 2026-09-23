package app

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const testHostKey = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
const testWorkspace = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"

func TestSyncArgumentParsing(t *testing.T) {
	f, err := parseSync([]string{"push", testWorkspace, "local folder", "--remote", "project/src", "--identity", "my key", "--dry-run", "--delete"})
	if err != nil {
		t.Fatal(err)
	}
	if f.direction != "push" || f.id != testWorkspace || f.local != "local folder" || f.remote != "project/src" || f.identity != "my key" || !f.dryRun || !f.delete {
		t.Fatalf("options = %#v", f)
	}
	for _, args := range [][]string{
		{"push", "bad", "folder"},
		{"pull", testWorkspace, "folder", "--remote", "/tmp"},
		{"pull", testWorkspace, "folder", "--remote", "workspace/../etc"},
		{"pull", testWorkspace, "folder", "--remote", "a//b"},
		{"push", testWorkspace, "folder", "--identity"},
		{"push", testWorkspace, "folder", "--unknown"},
	} {
		if _, err := parseSync(args); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestSSHConfigRenderingAndExclusions(t *testing.T) {
	config := renderSSHConfig(testWorkspace, "/tmp/my key")
	for _, want := range []string{
		"Host daemon-" + testWorkspace,
		"User dr-agent",
		"ProxyCommand npx --yes daemonsrun@latest ssh-proxy " + testWorkspace,
		"KnownHostsCommand npx --yes daemonsrun@latest ssh-known-hosts " + testWorkspace,
		"HostKeyAlias daemon-" + testWorkspace,
		"StrictHostKeyChecking yes",
		"UserKnownHostsFile /dev/null",
	} {
		if !strings.Contains(config, want) {
			t.Fatalf("missing %q", want)
		}
	}
	if strings.Contains(config, "User root") {
		t.Fatal("config selected root")
	}
	if !slices.Equal(syncExclusions(), []string{"--filter=:- .gitignore", "--exclude=node_modules/", "--exclude=vendor/"}) {
		t.Fatalf("exclusions = %v", syncExclusions())
	}
}

func TestHostKeyValidationAndPinChange(t *testing.T) {
	if !validHostKey(testHostKey) {
		t.Fatal("valid ed25519 key refused")
	}
	for _, key := range []string{"ssh-rsa AAAA", "ssh-ed25519 AAAA", testHostKey + " comment", testHostKey + "\nother"} {
		if validHostKey(key) {
			t.Fatalf("accepted %q", key)
		}
	}
	env := map[string]string{"HOME": t.TempDir()}
	if err := pinnedHostKey(testWorkspace, testHostKey, "https://daemons.run", env); err != nil {
		t.Fatal(err)
	}
	if err := pinnedHostKey(testWorkspace, testHostKey, "https://daemons.run", env); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(env["HOME"], ".ssh", "daemons-run", originHash("https://daemons.run"), "pins", testWorkspace)
	if err := os.WriteFile(path, []byte("ssh-ed25519 replacement\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := pinnedHostKey(testWorkspace, testHostKey, "https://daemons.run", env); err == nil {
		t.Fatal("changed pin accepted")
	}
}

func TestSSHProxyUsesCompiledEndpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch r.URL.Path {
		case "/api/v1/daemons/" + testWorkspace + "/ssh/ticket":
			fmt.Fprint(w, `{"data":{"ticket":"secret","gateway_url":"wss://attacker.example/ssh"}}`)
		case "/api/v1/daemons/" + testWorkspace + "/ssh":
			fmt.Fprintf(w, `{"data":{"enabled":true,"reconciled":true,"host_key":%q}}`, testHostKey)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	var out, errOut bytes.Buffer
	d := Dependencies{Output: &out, ErrorOutput: &errOut, Environment: map[string]string{"HOME": t.TempDir(), "DAEMONS_TOKEN": "test-token"}, HTTPClient: server.Client()}
	if code := Run(context.Background(), []string{"--host", server.URL, "ssh-proxy", testWorkspace}, d); code != 1 || !strings.Contains(errOut.String(), "gateway_url_mismatch") {
		t.Fatalf("mismatch exit=%d stderr=%q", code, errOut.String())
	}
	out.Reset()
	errOut.Reset()
	if code := Run(context.Background(), []string{"--host", server.URL, "ssh-known-hosts", testWorkspace}, d); code != 0 || out.String() != "daemon-"+testWorkspace+" "+testHostKey+"\n" {
		t.Fatalf("known hosts exit=%d stdout=%q stderr=%q", code, out.String(), errOut.String())
	}
}
