package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func productionFixture(t *testing.T, name string) []byte {
	t.Helper()
	payload, err := os.ReadFile(filepath.Join("testdata", "production", name))
	if err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSpace(payload)
}

func TestProductionResponseContracts(t *testing.T) {
	fixtures := map[string][]byte{
		"me":                   productionFixture(t, "me.json"),
		"capabilities":         productionFixture(t, "capabilities.json"),
		"servers":              productionFixture(t, "server-list.json"),
		"server":               productionFixture(t, "server-show.json"),
		"daemon":               productionFixture(t, "daemon-show.json"),
		"operation":            productionFixture(t, "operation-show.json"),
		"lifecycle":            productionFixture(t, "lifecycle.json"),
		"destroy":              productionFixture(t, "destroy.json"),
		"device-authorization": productionFixture(t, "device-authorization.json"),
		"terminal-ticket":      productionFixture(t, "terminal-ticket.json"),
	}
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("X-Daemons-Api-Version", "v1")
		var payload []byte
		switch {
		case request.URL.Path == "/api/v1":
			payload = []byte(`{"data":{"version":"v1"},"meta":[]}`)
		case request.URL.Path == "/api/v1/me":
			payload = fixtures["me"]
		case request.URL.Path == "/api/v1/capabilities":
			payload = fixtures["capabilities"]
		case request.URL.Path == "/api/v1/servers":
			payload = fixtures["servers"]
		case strings.HasPrefix(request.URL.Path, "/api/v1/servers/"):
			payload = fixtures["server"]
		case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/api/v1/daemons/") && !strings.Contains(request.URL.Path, "/terminal-tickets"):
			writer.Header().Set("ETag", `"production-etag"`)
			payload = fixtures["daemon"]
		case request.Method == http.MethodDelete && strings.HasPrefix(request.URL.Path, "/api/v1/daemons/"):
			payload = fixtures["destroy"]
		case strings.HasSuffix(request.URL.Path, "/start"):
			payload = fixtures["lifecycle"]
		case strings.HasPrefix(request.URL.Path, "/api/v1/operations/"):
			payload = fixtures["operation"]
		case request.URL.Path == "/api/v1/device-authorizations":
			writer.WriteHeader(http.StatusCreated)
			payload = fixtures["device-authorization"]
		case strings.HasSuffix(request.URL.Path, "/terminal-tickets"):
			payload = fixtures["terminal-ticket"]
		default:
			http.NotFound(writer, request)
			return
		}
		_, _ = writer.Write(payload)
	}))
	defer server.Close()

	api, err := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()))
	if err != nil {
		t.Fatal(err)
	}
	identity, err := api.Me(context.Background())
	if err != nil || identity.Meta == nil || identity.Data.Token.Restrictions == nil || !bytes.Equal(bytes.TrimSpace(identity.Raw), fixtures["me"]) {
		t.Fatalf("Me() = %#v, %v", identity, err)
	}
	capabilities, err := api.Capabilities(context.Background())
	if err != nil || len(capabilities.Data) != 4 || capabilities.Meta == nil || !bytes.Equal(bytes.TrimSpace(capabilities.Raw), fixtures["capabilities"]) {
		t.Fatalf("Capabilities() = %#v, %v", capabilities, err)
	}
	servers, err := api.ListServers(context.Background())
	if err != nil || len(servers.Data) != 1 || servers.Data[0].Capacity.MemoryGB != 4 || !bytes.Equal(bytes.TrimSpace(servers.Raw), fixtures["servers"]) {
		t.Fatalf("ListServers() = %#v, %v", servers, err)
	}
	serverResource, err := api.ShowServer(context.Background(), servers.Data[0].ID)
	if err != nil || serverResource.Data.Capacity.MemoryGB != 4 || serverResource.Meta == nil || !bytes.Equal(bytes.TrimSpace(serverResource.Raw), fixtures["server"]) {
		t.Fatalf("ShowServer() = %#v, %v", serverResource, err)
	}
	daemon, err := api.ShowDaemon(context.Background(), "01a034c7-f779-734a-8e45-73dbd3afcd33")
	if err != nil || daemon.ETag != `"production-etag"` || daemon.Meta == nil || !bytes.Equal(bytes.TrimSpace(daemon.Raw), fixtures["daemon"]) {
		t.Fatalf("ShowDaemon() = %#v, %v", daemon, err)
	}
	lifecycle, err := api.LifecycleDaemon(context.Background(), daemon.Data.ID, "start", "production-contract-key")
	if err != nil || lifecycle.Data.Status != "succeeded" || lifecycle.Meta == nil || !bytes.Equal(bytes.TrimSpace(lifecycle.Raw), fixtures["lifecycle"]) {
		t.Fatalf("LifecycleDaemon() = %#v, %v", lifecycle, err)
	}
	destroy, err := api.DestroyDaemon(context.Background(), "01a05ed6-dc52-734b-9dbf-2d224210ae8d", `"production-etag"`, "production-destroy-key")
	if err != nil || destroy.Data.Status != "succeeded" || destroy.Meta == nil || !bytes.Equal(bytes.TrimSpace(destroy.Raw), fixtures["destroy"]) {
		t.Fatalf("DestroyDaemon() = %#v, %v", destroy, err)
	}
	operation, err := api.ShowOperation(context.Background(), "01a04d0d-852a-7323-b07f-aec844e9a8f3")
	if err != nil || operation.Data.Result == nil || operation.Meta == nil || !bytes.Equal(bytes.TrimSpace(operation.Raw), fixtures["operation"]) {
		t.Fatalf("ShowOperation() = %#v, %v", operation, err)
	}
	authorization, err := api.CreateDeviceAuthorization(context.Background(), []string{"control-plane:discover"}, "7d")
	if err != nil || authorization.Data.IntervalSeconds != 5 || authorization.Meta == nil || !bytes.Equal(bytes.TrimSpace(authorization.Raw), fixtures["device-authorization"]) {
		t.Fatalf("CreateDeviceAuthorization() = %#v, %v", authorization, err)
	}
	ticket, err := api.MintTicket(context.Background(), daemon.Data.ID, "main", 80, 24)
	if err != nil || ticket.Data.Protocol != 1 || ticket.Data.GatewayURL == "" || ticket.Meta == nil {
		t.Fatalf("MintTicket() = %#v, %v", ticket, err)
	}
}

func TestEveryNumericResponseFieldAcceptsJSONStringNumbers(t *testing.T) {
	document := []byte(`{
		"server":{"data":{"capacity":{"cores":"2.00","memory_gb":"4.00","disk_gb":"80","daemon_count":"1.0"}}},
		"device":{"data":{"interval_seconds":"5"}},
		"ticket":{"data":{"expires_in":"30.0","terminal_protocol":"1"}},
		"task":{"data":{"timeout_seconds":"900.00"}},
		"files":{"data":[{"size":"4096.0","mtime":"1756720000"}]}
	}`)
	var response struct {
		Server ServerEnvelope      `json:"server"`
		Device DeviceAuthorization `json:"device"`
		Ticket Ticket              `json:"ticket"`
		Task   TaskEnvelope        `json:"task"`
		Files  FileList            `json:"files"`
	}
	if err := decodeResponseJSON(document, &response); err != nil {
		t.Fatal(err)
	}
	if response.Server.Data.Capacity.Cores != 2 || response.Server.Data.Capacity.MemoryGB != 4 || response.Server.Data.Capacity.DiskGB != 80 || response.Server.Data.Capacity.DaemonCount != 1 ||
		response.Device.Data.IntervalSeconds != 5 || response.Ticket.Data.ExpiresIn != 30 || response.Ticket.Data.Protocol != 1 || response.Task.Data.TimeoutSeconds != 900 ||
		len(response.Files.Data) != 1 || response.Files.Data[0].Size != 4096 || response.Files.Data[0].MTime != 1756720000 {
		t.Fatalf("decoded response = %#v", response)
	}
}

func TestUnexpectedNumericShapeNamesTheField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"data":{"id":"server-uuid","name":"host","status":"running","capacity":{"memory_gb":"4.25"}},"meta":[]}`)
	}))
	defer server.Close()
	api, _ := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()))
	_, err := api.ShowServer(context.Background(), "server-uuid")
	if err == nil || !strings.Contains(err.Error(), "data.capacity.memory_gb") || strings.Contains(err.Error(), "invalid JSON") {
		t.Fatalf("error = %v", err)
	}
}

func TestUnexpectedNumericShapeNamesTheIndexedField(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(writer, `{"data":[{"id":"first","name":"first-host","status":"running","capacity":{"memory_gb":"4"}},{"id":"second","name":"second-host","status":"running","capacity":{"memory_gb":false}}],"meta":{"next_cursor":null}}`)
	}))
	defer server.Close()
	api, _ := New(server.URL, "dr_cp_test", WithHTTPClient(server.Client()))
	_, err := api.ListServers(context.Background())
	if err == nil || !strings.Contains(err.Error(), "data[1].capacity.memory_gb") {
		t.Fatalf("error = %v", err)
	}
}

func TestWireIntRejectsNonJSONNumberStrings(t *testing.T) {
	for _, value := range []string{`"4/1"`, `"0x4"`, `"01"`, `"+4"`} {
		var decoded WireInt
		if err := json.Unmarshal([]byte(value), &decoded); err == nil {
			t.Fatalf("json.Unmarshal(%s) succeeded with %d", value, decoded)
		}
	}
}
