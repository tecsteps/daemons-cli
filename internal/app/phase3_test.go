package app

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
)

const (
	taskQueued    = `{"data":{"id":"task-uuid","daemon_id":"daemon-uuid","agent":"codex","model":null,"permission_mode":"yolo","working_directory":"/workspace","timeout_seconds":900,"expected_artifacts":[],"status":"queued","result":null,"error_code":null,"created_at":"2026-09-01T10:00:00+00:00","future":"kept"},"meta":{},"future_envelope":"kept"}`
	taskSucceeded = `{"data":{"id":"task-uuid","daemon_id":"daemon-uuid","agent":"codex","permission_mode":"yolo","working_directory":"/workspace","status":"succeeded","result":{"summary":"done","api_token":"dr_cp_leak"},"error_code":null,"finished_at":"2026-09-01T10:05:00+00:00"},"meta":{}}`
	taskFailed    = `{"data":{"id":"task-uuid","daemon_id":"daemon-uuid","agent":"codex","permission_mode":"yolo","status":"failed","result":{},"error_code":"agent_crashed"},"meta":{}}`
	taskCancelled = `{"data":{"id":"task-uuid","daemon_id":"daemon-uuid","agent":"codex","permission_mode":"yolo","status":"cancelling","result":null,"error_code":null},"meta":{"cancellation":"cancellation_requested_process_may_remain"}}`
	daemonList    = `{"data":[{"id":"daemon-uuid","name":"research","status":"running","primary_agent":"codex","server":{"id":"server-uuid","name":"host","status":"running"}}],"meta":{}}`
	filesPageOne  = `{"data":[{"name":"src","type":"directory","size":4096,"mtime":1756720000},{"name":"README.md","type":"file","size":120,"mtime":1756720100}],"meta":{"next_cursor":"c2"},"future":"kept"}`
	filesPageTwo  = `{"data":[{"name":"notes.txt","type":"file","size":10,"mtime":1756720200}],"meta":{"next_cursor":null}}`
	logsSnapshot  = `{"data":[{"timestamp":"2026-09-01T10:00:00+00:00","level":"info","source":"agent","message":"started"},{"timestamp":null,"level":"error","source":"agent","message":"token dr_cp_leaked_in_log rejected"}],"meta":{"next_cursor":"42"}}`
)

func TestPhaseThreeCommandsPreserveCanonicalJSON(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		stdin     string
		responses map[string]string
		want      []string
		key       string
		body      map[string]any
		stdout    string
	}{
		{
			name:      "task run by daemon uuid with positional prompt",
			arguments: []string{"task", "run", "11111111-2222-3333-4444-555555555555", "Write tests", "--agent", "codex", "--permission-mode", "approval-auto-deny", "--working-directory", "/workspace/app", "--timeout", "120", "--model", "gpt-5", "--idempotency-key", "phase3-task-key"},
			responses: map[string]string{"POST /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks": taskQueued},
			want:      []string{"GET /api/v1", "POST /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks"},
			key:       "phase3-task-key",
			body:      map[string]any{"prompt": "Write tests", "agent": "codex", "permission_mode": "approval-auto-deny", "working_directory": "/workspace/app", "timeout_seconds": float64(120), "model": "gpt-5"},
		},
		{
			name:      "task run resolves the daemon name and reads the prompt from stdin",
			arguments: []string{"task", "run", "research", "-", "--idempotency-key", "phase3-task-key"},
			stdin:     "Line one\nLine two\n",
			responses: map[string]string{"GET /api/v1/daemons": daemonList, "POST /api/v1/daemons/daemon-uuid/tasks": taskQueued},
			want:      []string{"GET /api/v1/daemons", "GET /api/v1", "POST /api/v1/daemons/daemon-uuid/tasks"},
			key:       "phase3-task-key",
			body:      map[string]any{"prompt": "Line one\nLine two"},
		},
		{
			name:      "task show",
			arguments: []string{"task", "show", "research", "task-uuid"},
			responses: map[string]string{"GET /api/v1/daemons": daemonList, "GET /api/v1/daemons/daemon-uuid/tasks/task-uuid": taskSucceeded},
			want:      []string{"GET /api/v1/daemons", "GET /api/v1/daemons/daemon-uuid/tasks/task-uuid"},
		},
		{
			name:      "task cancel",
			arguments: []string{"task", "cancel", "11111111-2222-3333-4444-555555555555", "task-uuid", "--idempotency-key", "phase3-cancel-key"},
			responses: map[string]string{"POST /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks/task-uuid/cancel": taskCancelled},
			want:      []string{"GET /api/v1", "POST /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks/task-uuid/cancel"},
			key:       "phase3-cancel-key",
		},
		{
			name:      "task list",
			arguments: []string{"task", "list", "11111111-2222-3333-4444-555555555555", "--limit", "5"},
			responses: map[string]string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks?limit=5": `{"data":[{"id":"task-uuid","status":"queued","agent":"codex"}],"meta":{"next_cursor":null}}`},
			want:      []string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/tasks?limit=5"},
		},
		{
			name:      "files list with path cursor and limit",
			arguments: []string{"files", "list", "11111111-2222-3333-4444-555555555555", "src/app", "--cursor", "c1", "--limit", "50"},
			responses: map[string]string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files?cursor=c1&limit=50&path=src%2Fapp": filesPageTwo},
			want:      []string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files?cursor=c1&limit=50&path=src%2Fapp"},
		},
		{
			name:      "files list --all follows the cursor and writes one document per page",
			arguments: []string{"files", "list", "11111111-2222-3333-4444-555555555555", "--all"},
			responses: map[string]string{
				"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files":           filesPageOne,
				"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files?cursor=c2": filesPageTwo,
			},
			want:   []string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files", "GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/files?cursor=c2"},
			stdout: filesPageOne + "\n" + filesPageTwo + "\n",
		},
		{
			name:      "logs snapshot with a closed source",
			arguments: []string{"logs", "11111111-2222-3333-4444-555555555555", "--source", "agent", "--level", "error", "--cursor", "41", "--limit", "10"},
			responses: map[string]string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/logs?cursor=41&level=error&limit=10&source=agent": logsSnapshot},
			want:      []string{"GET /api/v1/daemons/11111111-2222-3333-4444-555555555555/logs?cursor=41&level=error&limit=10&source=agent"},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
				response, ok := test.responses[request.Method+" "+request.URL.RequestURI()]
				if !ok {
					t.Errorf("unexpected request %s %s", request.Method, request.URL.RequestURI())
					http.NotFound(writer, request)
					return
				}
				if request.Method != http.MethodGet {
					writer.WriteHeader(http.StatusAccepted)
				}
				io.WriteString(writer, response)
			})

			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			dependencies.Input = strings.NewReader(test.stdin)
			arguments := append([]string{"--json", "--host", server.URL}, test.arguments...)
			if code := Run(context.Background(), arguments, dependencies); code != 0 {
				t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
			}
			want := test.stdout
			if want == "" {
				want = test.responses[test.want[len(test.want)-1]] + "\n"
			}
			if output.String() != want || errorOutput.Len() != 0 {
				t.Fatalf("stdout = %q, stderr = %q, want %q", output.String(), errorOutput.String(), want)
			}
			if !slices.Equal(record.requests, test.want) {
				t.Fatalf("requests = %#v, want %#v", record.requests, test.want)
			}
			last := len(record.requests) - 1
			if record.headers[last].Get("Idempotency-Key") != test.key {
				t.Fatalf("headers = %v", record.headers[last])
			}
			if test.body != nil {
				got, _ := json.Marshal(record.bodies[last])
				want, _ := json.Marshal(test.body)
				if string(got) != string(want) {
					t.Fatalf("body = %s, want %s", got, want)
				}
			}
		})
	}
}

func TestPhaseThreeLocalValidationSendsNothing(t *testing.T) {
	tests := map[string][]string{
		"task run without prompt":            {"task", "run", "research", "--idempotency-key", "phase3-task-key"},
		"task run empty stdin prompt":        {"task", "run", "research", "-", "--idempotency-key", "phase3-task-key"},
		"task run bad permission mode":       {"task", "run", "research", "do it", "--permission-mode", "sudo", "--idempotency-key", "phase3-task-key"},
		"task run escaping working dir":      {"task", "run", "research", "do it", "--working-directory", "/workspace/../etc", "--idempotency-key", "phase3-task-key"},
		"task run outside workspace":         {"task", "run", "research", "do it", "--working-directory", "/etc", "--idempotency-key", "phase3-task-key"},
		"task run bad timeout":               {"task", "run", "research", "do it", "--timeout", "soon", "--idempotency-key", "phase3-task-key"},
		"task run non-interactive no key":    {"task", "run", "research", "do it"},
		"task run has no wait":               {"task", "run", "research", "do it", "--wait", "--idempotency-key", "phase3-task-key"},
		"task show needs the daemon parent":  {"task", "show", "task-uuid"},
		"task cancel non-interactive no key": {"task", "cancel", "research", "task-uuid"},
		"files list unsafe path":             {"files", "list", "research", "../etc"},
		"files list bad limit":               {"files", "list", "research", "--limit", "500"},
		"files list all with cursor":         {"files", "list", "research", "--all", "--cursor", "c1"},
		"logs without source":                {"logs", "research"},
		"logs unknown source":                {"logs", "research", "--source", "kernel"},
		"logs follow is unavailable":         {"logs", "research", "--source", "agent", "--follow"},
		"logs bad level":                     {"logs", "research", "--source", "agent", "--level", "VERY LOUD"},
	}
	for name, arguments := range tests {
		t.Run(name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
				http.Error(writer, "must not be called", http.StatusInternalServerError)
			})
			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			dependencies.Input = strings.NewReader("\n")
			code := Run(context.Background(), append([]string{"--host", server.URL}, arguments...), dependencies)
			if code != 2 || len(record.requests) != 0 {
				t.Fatalf("exit = %d, requests = %v, stderr = %q", code, record.requests, errorOutput.String())
			}
		})
	}
}

func TestTaskRunFailureBranches(t *testing.T) {
	t.Run("confirmation required for codex yolo exits 6 without a side effect", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			problem(writer, 409, "confirmation_required", "A Codex task in YOLO mode requires browser confirmation.", `{"confirmation_id":"confirmation-uuid","approve_url":"https://daemons.run/settings?tab=control-plane","expires_at":"2026-09-01T12:00:00+00:00"}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "run", "11111111-2222-3333-4444-555555555555", "do it", "--idempotency-key", "phase3-task-key"}, dependencies)
		if code != 6 || !strings.Contains(errorOutput.String(), "confirmation-uuid") || !strings.Contains(errorOutput.String(), "run this command again") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})

	t.Run("concurrency exceeded is a rate outcome", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Retry-After", "30")
			problem(writer, 429, "task_concurrency_exceeded", "The token or daemon already has the maximum number of active tasks.", `{"active_count":2,"limit":2,"retry_after":30}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "run", "11111111-2222-3333-4444-555555555555", "do it", "--idempotency-key", "phase3-task-key"}, dependencies)
		if code != 7 || !strings.Contains(errorOutput.String(), "task_concurrency_exceeded") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})

	t.Run("daemon not running is a definite failure", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			problem(writer, 409, "daemon_not_running", "Tasks can run only while the daemon is running.", `{}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "run", "11111111-2222-3333-4444-555555555555", "do it", "--idempotency-key", "phase3-task-key"}, dependencies)
		if code != 1 || !strings.Contains(errorOutput.String(), "daemon_not_running") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})

	t.Run("transport failure after dispatch is outcome unknown with task guidance", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Fatal("hijack unsupported")
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Fatal(err)
			}
			connection.Close()
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "run", "11111111-2222-3333-4444-555555555555", "do it", "--idempotency-key", "phase3-task-key"}, dependencies)
		stderr := errorOutput.String()
		if code != 8 || !strings.Contains(stderr, "daemons task list 11111111-2222-3333-4444-555555555555") || !strings.Contains(stderr, "--idempotency-key phase3-task-key") {
			t.Fatalf("exit = %d, stderr = %q", code, stderr)
		}
		if strings.Contains(stderr, "do it") {
			t.Fatal("prompt was echoed in the failure output")
		}
	})

	t.Run("unknown daemon name is not found", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			io.WriteString(writer, `{"data":[],"meta":{}}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "run", "missing", "do it", "--idempotency-key", "phase3-task-key"}, dependencies)
		if code != 4 {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})
}

func TestTaskShowHumanOutputAndExitCodes(t *testing.T) {
	t.Run("succeeded task redacts sensitive result keys", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			io.WriteString(writer, taskSucceeded)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "show", "11111111-2222-3333-4444-555555555555", "task-uuid"}, dependencies)
		if code != 0 || !strings.Contains(output.String(), "Task task-uuid: succeeded (codex, yolo)") || !strings.Contains(output.String(), "result.summary: done") {
			t.Fatalf("exit = %d, stdout = %q", code, output.String())
		}
		if strings.Contains(output.String(), "dr_cp_leak") {
			t.Fatalf("stdout leaked a credential: %q", output.String())
		}
	})

	t.Run("failed task exits 1 under its error code", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			io.WriteString(writer, taskFailed)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "show", "11111111-2222-3333-4444-555555555555", "task-uuid"}, dependencies)
		if code != 1 || !strings.Contains(errorOutput.String(), "agent_crashed") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
		output.Reset()
		errorOutput.Reset()
		code = Run(context.Background(), []string{"--json", "--host", server.URL, "task", "show", "11111111-2222-3333-4444-555555555555", "task-uuid"}, dependencies)
		if code != 1 || output.String() != taskFailed+"\n" || errorOutput.Len() != 0 {
			t.Fatalf("json exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
	})

	t.Run("missing task is not found", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			problem(writer, 404, "not_found", "The requested resource was not found.", `{}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		if code := Run(context.Background(), []string{"--host", server.URL, "task", "show", "11111111-2222-3333-4444-555555555555", "task-uuid"}, dependencies); code != 4 {
			t.Fatalf("exit = %d", code)
		}
	})
}

func TestTaskCancelBranches(t *testing.T) {
	t.Run("human output explains a pending cancellation", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			writer.WriteHeader(http.StatusAccepted)
			io.WriteString(writer, taskCancelled)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "cancel", "11111111-2222-3333-4444-555555555555", "task-uuid", "--idempotency-key", "phase3-cancel-key"}, dependencies)
		if code != 0 || !strings.Contains(output.String(), "cancelling") || !strings.Contains(errorOutput.String(), "may keep running") {
			t.Fatalf("exit = %d, stdout = %q, stderr = %q", code, output.String(), errorOutput.String())
		}
	})

	t.Run("terminal task is not cancellable", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			problem(writer, 409, "task_not_cancellable", "This task has already reached a terminal state.", `{}`)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "task", "cancel", "11111111-2222-3333-4444-555555555555", "task-uuid", "--idempotency-key", "phase3-cancel-key"}, dependencies)
		if code != 1 || !strings.Contains(errorOutput.String(), "task_not_cancellable") {
			t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
		}
	})
}

func TestFilesListHumanOutputAndFailures(t *testing.T) {
	t.Run("single page prints a table and the next cursor hint", func(t *testing.T) {
		server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			io.WriteString(writer, filesPageOne)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "files", "list", "11111111-2222-3333-4444-555555555555"}, dependencies)
		lines := strings.Split(strings.TrimSpace(output.String()), "\n")
		if code != 0 || len(lines) != 3 || !strings.HasPrefix(lines[0], "TYPE") || !strings.Contains(lines[1], "directory") || !strings.Contains(lines[2], "README.md") {
			t.Fatalf("exit = %d, stdout = %q", code, output.String())
		}
		if !strings.Contains(errorOutput.String(), "--cursor c2") {
			t.Fatalf("stderr = %q", errorOutput.String())
		}
	})

	t.Run("--all stops at the page bound with a resumable cursor", func(t *testing.T) {
		server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
			io.WriteString(writer, filesPageOne)
		})
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
		code := Run(context.Background(), []string{"--host", server.URL, "files", "list", "11111111-2222-3333-4444-555555555555", "--all"}, dependencies)
		if code != 1 || len(record.requests) != maximumListPages || !strings.Contains(errorOutput.String(), "listing_truncated") {
			t.Fatalf("exit = %d, requests = %d, stderr = %q", code, len(record.requests), errorOutput.String())
		}
	})

	for _, test := range []struct {
		code   string
		status int
		exit   int
	}{
		{"daemon_not_running", 409, 1},
		{"file_not_found", 404, 4},
		{"workspace_path_type_invalid", 422, 1},
		{"daemon_unreachable", 503, 1},
	} {
		t.Run(test.code, func(t *testing.T) {
			server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
				problem(writer, test.status, test.code, "Problem detail.", `{}`)
			})
			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			code := Run(context.Background(), []string{"--host", server.URL, "files", "list", "11111111-2222-3333-4444-555555555555", "src"}, dependencies)
			if code != test.exit || !strings.Contains(errorOutput.String(), test.code) {
				t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
			}
		})
	}
}

func TestLogsHumanOutputRedactsAndHintsCursor(t *testing.T) {
	server, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
		io.WriteString(writer, logsSnapshot)
	})
	var output, errorOutput bytes.Buffer
	dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
	code := Run(context.Background(), []string{"--host", server.URL, "logs", "research-uuid-less", "--source", "provisioning"}, dependencies)
	if code != 4 {
		t.Fatalf("name resolution should 404 on an unknown daemon, exit = %d", code)
	}

	output.Reset()
	errorOutput.Reset()
	code = Run(context.Background(), []string{"--host", server.URL, "logs", "11111111-2222-3333-4444-555555555555", "--source", "agent"}, dependencies)
	if code != 0 {
		t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
	}
	stdout := output.String()
	if !strings.Contains(stdout, "2026-09-01T10:00:00+00:00 INFO started") || !strings.Contains(stdout, "- ERROR token [REDACTED] rejected") {
		t.Fatalf("stdout = %q", stdout)
	}
	if !strings.Contains(errorOutput.String(), "--source agent --cursor 42") {
		t.Fatalf("stderr = %q", errorOutput.String())
	}

	server2, _ := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, _ *http.Request) {
		problem(writer, 403, "scope_denied", "The token lacks logs:read.", `{}`)
	})
	output.Reset()
	errorOutput.Reset()
	if code := Run(context.Background(), []string{"--host", server2.URL, "logs", "11111111-2222-3333-4444-555555555555", "--source", "daemon"}, dependencies); code != 5 {
		t.Fatalf("scope denial exit = %d", code)
	}
}
