package app

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDownloadPublishesOnlyCompleteFilesWithoutOverwriting(t *testing.T) {
	for _, mode := range []string{"success", "truncated", "concurrent_destination", "existing_destination"} {
		t.Run(mode, func(t *testing.T) {
			const daemon = "11111111-2222-4333-8444-555555555555"
			const selector = "private-folder/report.txt"
			payload := strings.Repeat("synthetic-private-content\x00", 8192)
			directory := t.TempDir()
			destination := filepath.Join(directory, "result.bin")
			requests := 0
			if mode == "existing_destination" {
				if err := os.WriteFile(destination, []byte("preserved"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				requests++
				w.Header().Set("X-Daemons-Api-Version", "v1")
				if r.URL.RawQuery != "" {
					t.Error("selector leaked into URL")
				}
				switch r.URL.Path {
				case "/api/v1":
					io.WriteString(w, `{"data":{"version":"v1","workspace_access":{"ticket_version":2}}}`)
				case "/api/v1/daemons/" + daemon + "/access-tickets":
					var metadata map[string]string
					if err := json.NewDecoder(r.Body).Decode(&metadata); err != nil {
						t.Error(err)
					}
					if len(metadata) != 2 || metadata["action"] != "files.download" || metadata["operation_uuid"] == "" {
						t.Error("invalid metadata-only ticket request")
					}
					fmt.Fprintf(w, `{"data":{"ticket":"opaque.ticket","ticket_version":2,"expires_in":30,"method":"POST","gateway_path":"/v1/workspaces/%s/files/downloads"}}`, daemon)
				case "/v1/workspaces/" + daemon + "/files/downloads":
					if r.Method != "POST" || r.Header.Get("Authorization") != "DaemonsTicket opaque.ticket" {
						t.Error("incorrect relay admission")
					}
					var body map[string]string
					if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
						t.Error(err)
					}
					if len(body) != 1 || body["path"] != selector {
						t.Error("wrong guest selector")
					}
					if mode == "concurrent_destination" {
						if err := os.WriteFile(destination, []byte("preserved"), 0600); err != nil {
							t.Error(err)
						}
					}
					if mode == "truncated" {
						w.Header().Set("Content-Length", fmt.Sprint(len(payload)+1))
					}
					io.WriteString(w, payload)
				default:
					t.Error("unexpected endpoint")
					w.WriteHeader(404)
				}
			}))
			defer server.Close()
			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			code := Run(context.Background(), []string{"--json", "--host", server.URL, "files", "download", daemon, selector, destination}, dependencies)
			if strings.Contains(output.String()+errorOutput.String(), "synthetic-private-content") {
				t.Fatal("content leaked into command output")
			}
			contents, readErr := os.ReadFile(destination)
			if mode == "success" {
				if code != 0 || readErr != nil || string(contents) != payload {
					t.Fatalf("download failed: exit=%d error=%v stderr=%s", code, readErr, errorOutput.String())
				}
				info, err := os.Stat(destination)
				if err != nil || info.Mode().Perm() != 0600 {
					t.Fatal("download permissions")
				}
			} else {
				if code == 0 {
					t.Fatal("incomplete or conflicting download succeeded")
				}
				if mode == "truncated" {
					if !os.IsNotExist(readErr) {
						t.Fatal("partial destination retained")
					}
				} else if readErr != nil || string(contents) != "preserved" {
					t.Fatal("existing destination changed")
				}
			}
			if mode == "existing_destination" && requests != 0 {
				t.Fatal("existing destination performed network requests")
			}
			leftovers, err := filepath.Glob(filepath.Join(directory, ".daemons-download-*"))
			if err != nil || len(leftovers) != 0 {
				t.Fatal("temporary download was retained")
			}
		})
	}
}
