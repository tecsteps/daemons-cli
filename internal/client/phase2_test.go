package client

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func phaseTwoServer(t *testing.T, handler func(writer http.ResponseWriter, request *http.Request)) *Client {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		if request.URL.Path == "/api/v1" {
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
			return
		}
		handler(writer, request)
	}))
	t.Cleanup(server.Close)
	api, err := New(server.URL, "dr_cp_test")
	if err != nil {
		t.Fatal(err)
	}
	return api
}

func TestShowDaemonCapturesETag(t *testing.T) {
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("ETag", `"abc123"`)
		io.WriteString(writer, `{"data":{"id":"daemon-uuid","name":"research","status":"running"},"meta":{}}`)
	})
	result, err := api.ShowDaemon(context.Background(), "daemon-uuid")
	if err != nil || result.ETag != `"abc123"` {
		t.Fatalf("err = %v, etag = %q", err, result.ETag)
	}
}

func TestDestroyDaemonSendsIfMatchAndIdempotencyKey(t *testing.T) {
	var got http.Header
	method := ""
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		got = request.Header.Clone()
		method = request.Method + " " + request.URL.Path
		writer.WriteHeader(http.StatusAccepted)
		io.WriteString(writer, `{"data":{"id":"op","type":"daemon.destroy","status":"succeeded"},"meta":{}}`)
	})
	result, err := api.DestroyDaemon(context.Background(), "daemon-uuid", `"abc123"`, "destroy-key-1")
	if err != nil || result.Data.Status != "succeeded" {
		t.Fatalf("err = %v, result = %+v", err, result)
	}
	if method != "DELETE /api/v1/daemons/daemon-uuid" || got.Get("If-Match") != `"abc123"` || got.Get("Idempotency-Key") != "destroy-key-1" {
		t.Fatalf("method = %q, headers = %v", method, got)
	}
}

func TestSpawnDaemonBodyOmitsUnsetOptionalFields(t *testing.T) {
	var body map[string]any
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		_ = json.NewDecoder(request.Body).Decode(&body)
		writer.WriteHeader(http.StatusAccepted)
		io.WriteString(writer, `{"data":{"id":"daemon-uuid","name":"research","status":"provisioning","server":{"id":"server-uuid","name":"host","status":"running"}},"meta":{"operation":{"id":"op","type":"daemon.spawn","status":"queued"}}}`)
	})
	result, err := api.SpawnDaemon(context.Background(), SpawnRequest{ServerID: "server-uuid", Name: "research"}, "spawn-key-1")
	if err != nil || result.Meta.Operation.ID != "op" || result.Data.ID != "daemon-uuid" {
		t.Fatalf("err = %v, result = %+v", err, result)
	}
	if len(body) != 2 || body["server_id"] != "server-uuid" || body["name"] != "research" {
		t.Fatalf("body = %v", body)
	}

	result, err = api.SpawnDaemon(context.Background(), SpawnRequest{ServerID: "server-uuid", Name: "research", PrimaryAgent: "codex", DiskQuotaGB: 20}, "spawn-key-2")
	if err != nil || body["primary_agent"] != "codex" || body["disk_quota_gb"] != float64(20) {
		t.Fatalf("err = %v, body = %v", err, body)
	}
}

func TestSpawnDaemonWithoutOperationIsOutcomeUnknown(t *testing.T) {
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusAccepted)
		io.WriteString(writer, `{"data":{"id":"daemon-uuid","name":"research","status":"provisioning"},"meta":{}}`)
	})
	_, err := api.SpawnDaemon(context.Background(), SpawnRequest{ServerID: "server-uuid", Name: "research"}, "spawn-key-3")
	if errs.Code(err) != "outcome_unknown" || errs.ExitCode(err) != 8 {
		t.Fatalf("err = %v, code = %q", err, errs.Code(err))
	}
}

func TestListOperationsSendsLimitQuery(t *testing.T) {
	query := ""
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		query = request.URL.Path + "?" + request.URL.RawQuery
		io.WriteString(writer, `{"data":[{"id":"op","type":"daemon.start","status":"succeeded"}],"meta":{"next_cursor":null}}`)
	})
	result, err := api.ListOperations(context.Background(), 25)
	if err != nil || len(result.Data) != 1 || query != "/api/v1/operations?limit=25" {
		t.Fatalf("err = %v, query = %q, result = %+v", err, query, result)
	}
	if _, err := api.ListOperations(context.Background(), 0); err != nil || query != "/api/v1/operations?" {
		t.Fatalf("err = %v, query = %q", err, query)
	}
}

func TestListOperationsRejectsMissingDiscriminator(t *testing.T) {
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, `{"data":[{"id":"op","type":"daemon.start"}],"meta":{}}`)
	})
	if _, err := api.ListOperations(context.Background(), 0); errs.Code(err) != "invalid_response" {
		t.Fatalf("err = %v", err)
	}
}

func TestResolveServerMatchesExactNameOrID(t *testing.T) {
	api := phaseTwoServer(t, func(writer http.ResponseWriter, request *http.Request) {
		io.WriteString(writer, `{"data":[{"id":"server-uuid","name":"host","status":"running"},{"id":"other-uuid","name":"hostname","status":"running"}],"meta":{}}`)
	})
	server, err := api.ResolveServer(context.Background(), "host")
	if err != nil || server.ID != "server-uuid" {
		t.Fatalf("err = %v, server = %+v", err, server)
	}
	if _, err := api.ResolveServer(context.Background(), "hos"); errs.ExitCode(err) != 4 {
		t.Fatalf("prefix match must not resolve: err = %v", err)
	}
}
