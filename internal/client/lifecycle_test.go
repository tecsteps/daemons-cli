package client

import (
	"context"
	"io"
	"net/http"
	"sync/atomic"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func TestE7OperationProjectionShapes(t *testing.T) {
	for _, raw := range []string{
		`{"data":{"id":"op","type":"daemon.resume","state":"awaiting_payload","phase":"awaiting_payload","daemon_id":"workspace","reason_code":null,"retryable":false,"receipts":[]},"meta":[]}`,
		`{"data":{"id":"op","type":"daemon.start","status":"queued","result":[]},"meta":[]}`,
	} {
		api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, raw) })
		result, err := api.ShowOperation(context.Background(), "op")
		if err != nil || result.Data.ID != "op" || result.Data.Status == "" || string(result.Raw) != raw {
			t.Fatalf("result %+v, error %v", result, err)
		}
	}
}

func TestE7CompactLifecycleAcknowledgement(t *testing.T) {
	raw := `{"data":{"uuid":"op","status":"queued"},"meta":[]}`
	api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Match") != `"revision"` || r.Header.Get("Idempotency-Key") != "exact-key-1" {
			t.Errorf("headers %v", r.Header)
		}
		io.WriteString(w, raw)
	})
	result, err := api.LifecycleDaemonWithOptions(context.Background(), "workspace", "resume", `"revision"`, "exact-key-1", nil)
	if err != nil || result.Data.ID != "op" || result.Data.Type != "daemon.resume" || string(result.Raw) != raw {
		t.Fatalf("result %+v, error %v", result, err)
	}
}

func TestE7BulkRejectsMissingOrForeignOutcomes(t *testing.T) {
	for _, raw := range []string{`{"data":{"outcomes":[]},"meta":[]}`, `{"data":{"outcomes":[{"daemon_id":"foreign","operation_id":"op","status":"accepted","code":null}]},"meta":[]}`} {
		api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, raw) })
		_, err := api.BulkDaemons(context.Background(), "stop", []string{"workspace"}, "exact-key-1")
		if errs.ExitCode(err) != 8 {
			t.Fatalf("error %v", err)
		}
	}
}

func TestE7MutationTransportRetriesPreserveExactKeyAndBody(t *testing.T) {
	var calls atomic.Int32
	api := phaseTwoServer(t, func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(r.Body)
		if r.Header.Get("Idempotency-Key") != "exact-key-1" || r.Header.Get("If-Match") != `"revision"` || string(body) != `{"force":true}` {
			t.Errorf("replay changed request: %v %s", r.Header, body)
		}
		connection, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		connection.Close()
	})
	_, err := api.LifecycleDaemonWithOptions(context.Background(), "workspace", "restart", `"revision"`, "exact-key-1", map[string]any{"force": true})
	if count := calls.Load(); errs.ExitCode(err) != 8 || count < 1 || count > 2 {
		t.Fatalf("calls %d error %v", count, err)
	}
}
