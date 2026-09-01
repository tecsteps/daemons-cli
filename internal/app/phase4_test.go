package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/credentials"
	"github.com/tecsteps/daemons-cli/internal/upload"
)

const meResponse = `{"data":{"account":{"id":"user-uuid","email":"developer@example.test","control_plane_api_enabled":true},"token":{"id":"token-uuid","name":"CLI","scopes":[],"restrictions":[],"expires_at":"2030-01-01T00:00:00Z"}},"meta":[]}`

func normalizedHost(t *testing.T, raw string) string {
	t.Helper()
	normalized, err := client.NormalizeBaseURL(raw)
	if err != nil {
		t.Fatal(err)
	}
	return normalized
}

func storedDependencies(t *testing.T, httpClient *http.Client, output, errorOutput *bytes.Buffer) (Dependencies, string) {
	t.Helper()
	directory := t.TempDir()
	credentialPath := filepath.Join(directory, "credentials.json")
	return Dependencies{
		Output:        output,
		ErrorOutput:   errorOutput,
		Environment:   map[string]string{"HOME": directory, "DAEMONS_CREDENTIALS_FILE": credentialPath},
		HTTPClient:    httpClient,
		Now:           func() time.Time { return time.Date(2029, 1, 1, 0, 0, 0, 0, time.UTC) },
		IsInteractive: func() bool { return false },
	}, credentialPath
}

func TestLoginTokenStdin(t *testing.T) {
	newServer := func(t *testing.T, expectToken string) (*http.Client, string) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path != "/api/v1/me" {
				t.Errorf("unexpected request %s", request.URL.Path)
				http.NotFound(writer, request)
				return
			}
			if request.Header.Get("Authorization") != "Bearer "+expectToken {
				problem(writer, 401, "authentication_failed", "The token is invalid.", `{}`)
				return
			}
			io.WriteString(writer, meResponse)
		})
		return server.Client(), server.URL
	}

	t.Run("stores a verified token under the normalized host without echoing it", func(t *testing.T) {
		httpClient, host := newServer(t, "dr_cp_from_stdin")
		var output, errorOutput bytes.Buffer
		dependencies, credentialPath := storedDependencies(t, httpClient, &output, &errorOutput)
		dependencies.Input = strings.NewReader("dr_cp_from_stdin\n")
		if code := Run(context.Background(), []string{"--host", host, "login", "--token-stdin"}, dependencies); code != 0 {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
		if strings.Contains(output.String()+errorOutput.String(), "dr_cp_from_stdin") {
			t.Fatal("token was echoed")
		}
		if !strings.Contains(output.String(), "developer@example.test") {
			t.Fatalf("stdout = %q", output.String())
		}
		credential, err := (credentials.Store{Path: credentialPath}).Load(normalizedHost(t, host))
		if err != nil || credential.Token != "dr_cp_from_stdin" || credential.ExpiresAt != "2030-01-01T00:00:00Z" {
			t.Fatalf("stored credential = %#v, %v", credential, err)
		}

		output.Reset()
		if code := Run(context.Background(), []string{"--json", "--host", host, "whoami"}, dependencies); code != 0 || !strings.Contains(output.String(), "developer@example.test") {
			t.Fatalf("whoami with stored token exit = %d, stdout = %q", code, output.String())
		}
	})

	t.Run("a rejected token is not stored", func(t *testing.T) {
		httpClient, host := newServer(t, "dr_cp_other")
		var output, errorOutput bytes.Buffer
		dependencies, credentialPath := storedDependencies(t, httpClient, &output, &errorOutput)
		dependencies.Input = strings.NewReader("dr_cp_wrong\n")
		if code := Run(context.Background(), []string{"--host", host, "login", "--token-stdin"}, dependencies); code != 3 {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
		if _, err := os.Stat(credentialPath); !os.IsNotExist(err) {
			t.Fatal("credential file was written for a rejected token")
		}
		if strings.Contains(errorOutput.String(), "dr_cp_wrong") {
			t.Fatal("token leaked into stderr")
		}
	})

	for name, test := range map[string]struct {
		stdin     string
		arguments []string
	}{
		"empty stdin":            {"\n", []string{"login", "--token-stdin"}},
		"two tokens on stdin":    {"dr_cp_a dr_cp_b\n", []string{"login", "--token-stdin"}},
		"scope with token-stdin": {"dr_cp_a\n", []string{"login", "--token-stdin", "--scope", "daemons:read"}},
		"token as argument":      {"", []string{"login", "--token", "dr_cp_a"}},
	} {
		t.Run(name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "must not be called", http.StatusInternalServerError)
			})
			var output, errorOutput bytes.Buffer
			dependencies, credentialPath := storedDependencies(t, server.Client(), &output, &errorOutput)
			dependencies.Input = strings.NewReader(test.stdin)
			code := Run(context.Background(), append([]string{"--host", server.URL}, test.arguments...), dependencies)
			if code != 2 || len(record.requests) != 0 {
				t.Fatalf("exit = %d, requests = %v, stderr = %q", code, record.requests, errorOutput.String())
			}
			if _, err := os.Stat(credentialPath); !os.IsNotExist(err) {
				t.Fatal("credential file was written")
			}
			if strings.Contains(errorOutput.String(), "dr_cp_a") {
				t.Fatal("token leaked into stderr")
			}
		})
	}
}

func TestCredentialsAreIsolatedPerHost(t *testing.T) {
	newHost := func(t *testing.T, token string) (*http.Client, string) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.Header.Get("Authorization") != "Bearer "+token {
				problem(writer, 401, "authentication_failed", "Wrong host token.", `{}`)
				return
			}
			switch request.URL.Path {
			case "/api/v1/me":
				io.WriteString(writer, meResponse)
			case "/api/v1/tokens/current":
				io.WriteString(writer, `{"data":{"revoked":true},"meta":{}}`)
			default:
				http.NotFound(writer, request)
			}
		})
		return server.Client(), server.URL
	}
	firstClient, firstHost := newHost(t, "dr_cp_first")
	secondClient, secondHost := newHost(t, "dr_cp_second")

	var output, errorOutput bytes.Buffer
	dependencies, credentialPath := storedDependencies(t, firstClient, &output, &errorOutput)
	dependencies.Input = strings.NewReader("dr_cp_first\n")
	if code := Run(context.Background(), []string{"--host", firstHost, "login", "--token-stdin"}, dependencies); code != 0 {
		t.Fatalf("first login exit = %d, stderr = %q", code, errorOutput.String())
	}
	dependencies.HTTPClient = secondClient
	dependencies.Input = strings.NewReader("dr_cp_second\n")
	if code := Run(context.Background(), []string{"--host", secondHost, "login", "--token-stdin"}, dependencies); code != 0 {
		t.Fatalf("second login exit = %d, stderr = %q", code, errorOutput.String())
	}

	store := credentials.Store{Path: credentialPath}
	first, err := store.Load(normalizedHost(t, firstHost))
	if err != nil || first.Token != "dr_cp_first" {
		t.Fatalf("first host credential = %#v, %v (second login overwrote it)", first, err)
	}

	// Both hosts stay usable: each request carries its own host's token.
	dependencies.HTTPClient = firstClient
	if code := Run(context.Background(), []string{"--host", firstHost, "whoami"}, dependencies); code != 0 {
		t.Fatalf("first host whoami exit = %d, stderr = %q", code, errorOutput.String())
	}
	dependencies.HTTPClient = secondClient
	if code := Run(context.Background(), []string{"--host", secondHost, "whoami"}, dependencies); code != 0 {
		t.Fatalf("second host whoami exit = %d, stderr = %q", code, errorOutput.String())
	}

	// Without --host two non-production hosts are ambiguous, never guessed.
	errorOutput.Reset()
	if code := Run(context.Background(), []string{"whoami"}, dependencies); code != 3 || !strings.Contains(errorOutput.String(), "credential_host_ambiguous") {
		t.Fatalf("ambiguous host exit = %d, stderr = %q", code, errorOutput.String())
	}

	// An unknown host is authentication_required for that host, not a mismatch against another.
	errorOutput.Reset()
	if code := Run(context.Background(), []string{"--host", "https://third.example.test", "whoami"}, dependencies); code != 3 || !strings.Contains(errorOutput.String(), "https://third.example.test/api/v1") {
		t.Fatalf("unknown host exit = %d, stderr = %q", code, errorOutput.String())
	}

	// Logout on one host revokes and removes only that host's credential.
	if code := Run(context.Background(), []string{"--host", secondHost, "logout"}, dependencies); code != 0 {
		t.Fatalf("logout exit = %d, stderr = %q", code, errorOutput.String())
	}
	if _, err := store.Load(normalizedHost(t, secondHost)); err == nil {
		t.Fatal("second host credential survived logout")
	}
	if _, err := store.Load(normalizedHost(t, firstHost)); err != nil {
		t.Fatalf("first host credential removed by another host's logout: %v", err)
	}

	// With a single stored host left, no --host is needed.
	dependencies.HTTPClient = firstClient
	errorOutput.Reset()
	if code := Run(context.Background(), []string{"whoami"}, dependencies); code != 0 {
		t.Fatalf("single host whoami exit = %d, stderr = %q", code, errorOutput.String())
	}
}

func TestLegacyCredentialFileKeepsWorkingAndMigrates(t *testing.T) {
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
		if request.Header.Get("Authorization") != "Bearer dr_cp_legacy" {
			problem(writer, 401, "authentication_failed", "Wrong token.", `{}`)
			return
		}
		io.WriteString(writer, meResponse)
	})
	var output, errorOutput bytes.Buffer
	dependencies, credentialPath := storedDependencies(t, server.Client(), &output, &errorOutput)
	legacy := `{"version":1,"base_url":"` + normalizedHost(t, server.URL) + `","token":"dr_cp_legacy","account_email":"developer@example.test"}`
	if err := os.WriteFile(credentialPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := Run(context.Background(), []string{"whoami"}, dependencies); code != 0 {
		t.Fatalf("legacy whoami exit = %d, stderr = %q", code, errorOutput.String())
	}
}

func uploadFixture(t *testing.T, names ...string) []string {
	t.Helper()
	directory := t.TempDir()
	paths := make([]string, 0, len(names))
	for _, name := range names {
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte("content of "+name), 0o600); err != nil {
			t.Fatal(err)
		}
		paths = append(paths, path)
	}
	return paths
}

func TestUploadPartialResultFixtures(t *testing.T) {
	t.Run("mid-batch storage failure reports the partial result and stops", func(t *testing.T) {
		uploads := 0
		server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/api/v1/daemons" {
				io.WriteString(writer, daemonList)
				return
			}
			uploads++
			if uploads == 2 {
				problem(writer, 507, "daemon_storage_full", "The daemon is out of storage space for dr_cp_should_not_show.", `{}`)
				return
			}
			io.WriteString(writer, `{"ok":true,"path":"/root/workspace/uploads/file`+itoa(uploads)+`.txt"}`)
		})
		paths := uploadFixture(t, "one.txt", "two.txt", "three.txt")
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), append([]string{"--json", "--host", server.URL, "upload", "research"}, paths...), dependencies)
		if code != 7 || uploads != 2 {
			t.Fatalf("exit = %d, uploads = %d, stderr = %q, requests = %v", code, uploads, errorOutput.String(), record.requests)
		}
		var report upload.Report
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatalf("report = %q: %v", output.String(), err)
		}
		statuses := []string{report.Data.Results[0].Status, report.Data.Results[1].Status, report.Data.Results[2].Status}
		if strings.Join(statuses, ",") != "uploaded,not_attempted,not_attempted" || report.Meta.Uploaded != 1 || report.Meta.Requested != 3 {
			t.Fatalf("report = %+v", report)
		}
		if report.Error == nil || report.Error.Code != "daemon_storage_full" || report.Error.FailedIndex != 1 {
			t.Fatalf("report error = %+v", report.Error)
		}
		if strings.Contains(output.String(), "dr_cp_should_not_show") || !strings.Contains(report.Error.Message, "[REDACTED]") {
			t.Fatalf("report leaked a credential: %q", output.String())
		}
	})

	t.Run("transport failure after dispatch marks that file unknown and exits 8", func(t *testing.T) {
		uploads := 0
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/api/v1/daemons" {
				io.WriteString(writer, daemonList)
				return
			}
			uploads++
			if uploads == 2 {
				hijacker, ok := writer.(http.Hijacker)
				if !ok {
					t.Fatal("hijack unsupported")
				}
				connection, _, err := hijacker.Hijack()
				if err != nil {
					t.Fatal(err)
				}
				connection.Close()
				return
			}
			io.WriteString(writer, `{"ok":true,"path":"/root/workspace/uploads/file.txt"}`)
		})
		paths := uploadFixture(t, "one.txt", "two.txt", "three.txt")
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), append([]string{"--json", "--host", server.URL, "upload", "research"}, paths...), dependencies)
		if code != 8 {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
		var report upload.Report
		if err := json.Unmarshal(output.Bytes(), &report); err != nil {
			t.Fatalf("report = %q: %v", output.String(), err)
		}
		statuses := []string{report.Data.Results[0].Status, report.Data.Results[1].Status, report.Data.Results[2].Status}
		if strings.Join(statuses, ",") != "uploaded,unknown,not_attempted" || report.Meta.Uploaded != 1 {
			t.Fatalf("report = %+v", report)
		}
		if report.Error == nil || report.Error.Code != "upload_outcome_unknown" || report.Error.FailedIndex != 1 {
			t.Fatalf("report error = %+v", report.Error)
		}
		// The third file was never sent: no automatic retry, no continuation.
		if uploads != 2 {
			t.Fatalf("uploads = %d, want 2", uploads)
		}
	})

	t.Run("human mode prints only landed paths and the redacted failure", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
			if request.URL.Path == "/api/v1/daemons" {
				io.WriteString(writer, daemonList)
				return
			}
			problem(writer, 422, "unsafe_workspace_path", "Rejected token dr_cp_in_detail.", `{}`)
		})
		paths := uploadFixture(t, "one.txt")
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), append([]string{"--host", server.URL, "upload", "research"}, paths...), dependencies)
		if code != 1 || output.Len() != 0 || strings.Contains(errorOutput.String(), "dr_cp_in_detail") || !strings.Contains(errorOutput.String(), "[REDACTED]") {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
	})
}
