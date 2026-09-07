package client

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func TestV2CommandsKeepSelectorsAndUploadOutOfControlPlane(t *testing.T) {
	var relays atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		if r.URL.Path == "/api/v1" {
			io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
			return
		}
		if r.URL.Path == "/api/v1/daemons/workspace/access-tickets" {
			var metadata map[string]string
			if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
				t.Error(err)
			}
			if len(metadata) != 2 || metadata["operation_uuid"] == "" || r.URL.RawQuery != "" {
				t.Error("content entered metadata request")
			}
			suffix, method := "/files/query", "POST"
			if metadata["action"] == "logs.read" {
				suffix = "/logs/query"
			}
			if metadata["action"] == "files.upload" {
				suffix, method = "/files/uploads/"+metadata["operation_uuid"], "PUT"
			}
			json.NewEncoder(w).Encode(map[string]any{"data": map[string]any{"ticket": "opaque.ticket", "ticket_version": 2, "expires_in": 30, "method": method, "gateway_path": "/v1/workspaces/workspace" + suffix}})
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/v1/workspaces/workspace/") {
			t.Error("unexpected central content endpoint")
			w.WriteHeader(404)
			return
		}
		if r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" || r.URL.RawQuery != "" {
			t.Error("credential boundary")
		}
		relays.Add(1)
		if r.Method == "PUT" {
			var size [4]byte
			if _, err := io.ReadFull(r.Body, size[:]); err != nil {
				t.Error(err)
				return
			}
			length := binary.BigEndian.Uint32(size[:])
			if length > 16384 {
				t.Error("prelude limit")
				return
			}
			selector := make([]byte, length)
			io.ReadFull(r.Body, selector)
			if string(selector) != `{"path":"uploads/synthetic.txt"}` {
				t.Error("wrong selector")
			}
			var data strings.Builder
			io.Copy(&data, r.Body)
			if data.String() != "private-file-content" {
				t.Error("file bytes changed")
			}
			io.WriteString(w, `{"ok":true,"path":"/root/workspace/uploads/synthetic.txt"}`)
			return
		}
		var selector map[string]any
		if err := json.NewDecoder(r.Body).Decode(&selector); err != nil {
			t.Error(err)
		}
		if strings.HasSuffix(r.URL.Path, "/logs/query") {
			if selector["cursor"] != "private-cursor" {
				t.Error("wrong log selector")
			}
		} else if selector["path"] != "private-folder" {
			t.Error("wrong file selector")
		}
		io.WriteString(w, `{"data":[],"meta":{"next_cursor":null}}`)
	}))
	defer server.Close()
	c, _ := New(server.URL, "CP-SECRET")
	ctx := context.Background()
	if err := c.Preflight(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListFiles(ctx, "workspace", "private-folder", "", 20); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ListLogs(ctx, "workspace", "agent", "", "private-cursor", 20); err != nil {
		t.Fatal(err)
	}
	file, err := os.CreateTemp(t.TempDir(), "upload-")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	file.WriteString("private-file-content")
	file.Seek(0, 0)
	if result, err := c.Upload(ctx, "workspace", "synthetic.txt", file); err != nil || !result.OK {
		t.Fatalf("upload: %v", err)
	}
	if relays.Load() != 3 {
		t.Fatal("missing relay request")
	}
}

func TestAccessTicketNegotiationKeepsPathsOutOfControlPlane(t *testing.T) {
	var ticketCalls, relayCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		switch r.URL.Path {
		case "/api/v1":
			io.WriteString(w, `{"data":{"version":"v1"}}`)
		case "/api/v1/daemons/workspace/access-tickets":
			ticketCalls.Add(1)
			var metadata map[string]string
			if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
				t.Error(err)
			}
			if len(metadata) != 2 || metadata["action"] != "files.read" || metadata["operation_uuid"] != "operation" {
				t.Error("content in metadata request")
			}
			io.WriteString(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"POST","gateway_path":"/v1/workspaces/workspace/files/query"}}`)
		case "/v1/workspaces/workspace/files/query":
			relayCalls.Add(1)
			if r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
				t.Error("wrong credential")
			}
			io.Copy(w, r.Body)
		default:
			t.Errorf("unexpected endpoint %s", r.URL.Path)
			w.WriteHeader(404)
		}
	}))
	defer server.Close()
	c, _ := New(server.URL, "CP-SECRET")
	var output strings.Builder
	if err := c.AccessContent(context.Background(), "workspace", "operation", "files.read", strings.NewReader(`{"path":"guest-only-sentinel"}`), &output); err != nil {
		t.Fatal(err)
	}
	if ticketCalls.Load() != 1 || relayCalls.Load() != 1 || output.String() != `{"path":"guest-only-sentinel"}` {
		t.Fatal("incomplete transfer")
	}
}

func TestGatewayAuthorityIsExact(t *testing.T) {
	c, _ := New("https://control.example", "synthetic")
	for _, value := range []string{"https://evil.example/v1/workspaces/x", "https://control.example:444/v1/workspaces/x", "http://control.example/v1/workspaces/x", "https://control.example/v1/workspaces/x?ticket=secret", "https://control.example/v1/workspaces/x?", "https://user@control.example/v1/workspaces/x", "https://control.example/v1/%77orkspaces/x"} {
		if c.ValidateGatewayURL(value) == nil {
			t.Fatalf("accepted %s", value)
		}
	}
	for _, value := range []string{"https://control.example/v1/workspaces/x", "wss://control.example/ssh"} {
		if err := c.ValidateGatewayURL(value); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTicketMintDoesNotFollowRedirect(t *testing.T) {
	var minted atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Daemons-Api-Version", "v1")
		if r.URL.Path == "/api/v1" {
			io.WriteString(w, `{"data":{"version":"v1"}}`)
			return
		}
		minted.Add(1)
		w.Header().Set("Location", "/redirect-target")
		w.WriteHeader(307)
	}))
	defer server.Close()
	c, _ := New(server.URL, "CP-SECRET")
	if _, err := c.MintAccessTicket(context.Background(), "workspace", "operation", "files.read"); err == nil {
		t.Fatal("redirect accepted")
	}
	if minted.Load() != 1 {
		t.Fatal("ticket mint was replayed")
	}
}

func TestContentRelayStreamsWithoutControlPlaneTokenOrRedirectReplay(t *testing.T) {
	var received atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		if r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" || r.URL.RawQuery != "" {
			t.Error("credential boundary")
		}
		if strings.HasSuffix(r.URL.Path, "/redirect") {
			w.Header().Set("Location", "/sink")
			w.WriteHeader(307)
			return
		}
		io.Copy(w, r.Body)
	}))
	defer server.Close()
	c, _ := New(server.URL, "CP-SECRET")
	var output strings.Builder
	if err := c.RelayContent(context.Background(), server.URL+"/v1/workspaces/id/files/query", "opaque.ticket", strings.NewReader("guest-content"), &output); err != nil {
		t.Fatal(err)
	}
	if output.String() != "guest-content" {
		t.Fatal("content corrupted")
	}
	if err := c.RelayContent(context.Background(), server.URL+"/v1/workspaces/id/redirect", "opaque.ticket", strings.NewReader("not-replayed"), io.Discard); err == nil {
		t.Fatal("redirect accepted")
	}
	if received.Load() != 2 {
		t.Fatal("redirect followed or retried")
	}
}

func TestPartialDownloadIsNonzeroAndDoesNotExposeResponse(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", "100")
		io.WriteString(w, "synthetic-private-path")
	}))
	defer server.Close()
	c, _ := New(server.URL, "CP-SECRET")
	err := c.RelayContent(context.Background(), server.URL+"/v1/workspaces/id/files/query", "opaque.ticket", nil, io.Discard)
	if errs.ExitCode(err) != 8 || strings.Contains(err.Error(), "synthetic-private-path") {
		t.Fatalf("unexpected result: %v", err)
	}
}
