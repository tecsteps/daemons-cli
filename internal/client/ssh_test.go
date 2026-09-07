package client

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestSSHClientUsesNestedRoutes(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/daemons/a%20b/ssh" || r.Method != http.MethodGet {
			t.Fatalf("route %s %s", r.Method, r.URL.Path)
		}
		fmt.Fprint(w, `{"data":{"enabled":true,"reconciled":true,"host_key":"ssh-ed25519 AAAA","host_key_fingerprint":"SHA256:x","keys":[]},"meta":{}}`)
	}))
	defer server.Close()
	c, err := New(server.URL, "token")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.SSH(context.Background(), "a b"); err != nil {
		t.Fatal(err)
	}
}

func TestGatewayURLUsesDNSOnlySSHHost(t *testing.T) {
	c, err := New("https://daemons.run", "synthetic")
	if err != nil {
		t.Fatal(err)
	}
	if got := c.GatewayURL(); got != "wss://ssh.daemons.run:2222/ssh" {
		t.Fatalf("GatewayURL = %q", got)
	}
}
