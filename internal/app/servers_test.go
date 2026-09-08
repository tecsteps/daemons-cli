package app

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
)

const serverResource = `{"id":"server-uuid","name":"host","status":"running","region":"fsn1","capacity":{"cores":4,"memory_gb":16,"disk_gb":160,"daemon_count":3}}`

// TestServersCommandsAreDispatched proves the registry reaches the servers
// handlers advertised by help, with the exact API method and path.
func TestServersCommandsAreDispatched(t *testing.T) {
	tests := []struct {
		name      string
		arguments []string
		request   string
		body      string
		contains  []string
	}{
		{
			name:      "servers list",
			arguments: []string{"servers", "list"},
			request:   "GET /api/v1/servers",
			body:      `{"data":[` + serverResource + `],"meta":{}}`,
			contains:  []string{"NAME", "host", "running", "fsn1"},
		},
		{
			name:      "servers show",
			arguments: []string{"servers", "show", "server-uuid"},
			request:   "GET /api/v1/servers/server-uuid",
			body:      `{"data":` + serverResource + `,"meta":{}}`,
			contains:  []string{"ID: server-uuid", "Name: host", "Daemons: 3"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server, record := newPhaseTwoServer(t, func(_ *phaseTwoServer, writer http.ResponseWriter, request *http.Request) {
				if request.Method+" "+request.URL.RequestURI() != test.request {
					t.Errorf("unexpected request %s %s", request.Method, request.URL.RequestURI())
					http.NotFound(writer, request)
					return
				}
				io.WriteString(writer, test.body)
			})
			var output, errorOutput bytes.Buffer
			dependencies := phaseOneDependencies(t, server.Client(), &output, &errorOutput)
			arguments := append([]string{"--host", server.URL}, test.arguments...)
			if code := Run(context.Background(), arguments, dependencies); code != 0 {
				t.Fatalf("exit = %d, stderr = %q", code, errorOutput.String())
			}
			record.mu.Lock()
			requests := append([]string(nil), record.requests...)
			record.mu.Unlock()
			found := false
			for _, seen := range requests {
				if seen == test.request {
					found = true
				}
			}
			if !found {
				t.Fatalf("requests = %v, want %s", requests, test.request)
			}
			for _, want := range test.contains {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("stdout = %q, want %q", output.String(), want)
				}
			}
		})
	}
}
