package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

type rawEnvelope interface {
	setRaw(json.RawMessage)
}

// headerReceiver lets a typed envelope keep response headers that matter for
// later conditional requests or polling, such as ETag and Retry-After.
type headerReceiver interface {
	setResponseHeaders(http.Header)
}

type Account struct {
	ID      string `json:"id"`
	Email   string `json:"email"`
	Enabled bool   `json:"control_plane_api_enabled"`
}

type TokenInfo struct {
	ID           string         `json:"id"`
	Name         string         `json:"name"`
	Scopes       []string       `json:"scopes"`
	Restrictions map[string]any `json:"restrictions"`
	ExpiresAt    string         `json:"expires_at"`
}

type Me struct {
	Data struct {
		Account Account   `json:"account"`
		Token   TokenInfo `json:"token"`
	} `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *Me) setRaw(raw json.RawMessage) { response.Raw = raw }

type Daemon struct {
	ID           string `json:"id"`
	Name         string `json:"name"`
	Status       string `json:"status"`
	PrimaryAgent string `json:"primary_agent"`
	Server       struct {
		ID     string `json:"id"`
		Name   string `json:"name"`
		Status string `json:"status"`
	} `json:"server"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type DaemonList struct {
	Data []Daemon        `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *DaemonList) setRaw(raw json.RawMessage) { response.Raw = raw }

type DaemonEnvelope struct {
	Data Daemon          `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
	ETag string          `json:"-"`
}

func (response *DaemonEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

func (response *DaemonEnvelope) setResponseHeaders(headers http.Header) {
	response.ETag = headers.Get("ETag")
}

// DaemonSpawnEnvelope is the 202 document returned by POST /daemons: the new
// daemon plus the spawn Operation carried in meta.
type DaemonSpawnEnvelope struct {
	Data Daemon `json:"data"`
	Meta struct {
		Operation Operation `json:"operation"`
	} `json:"meta"`
	Raw json.RawMessage `json:"-"`
}

func (response *DaemonSpawnEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

type SpawnRequest struct {
	ServerID     string
	Name         string
	PrimaryAgent string
	DiskQuotaGB  int
}

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Region   string `json:"region"`
	Capacity struct {
		Cores             int  `json:"cores"`
		MemoryGB          int  `json:"memory_gb"`
		DiskGB            int  `json:"disk_gb"`
		DaemonCount       int  `json:"daemon_count"`
		EligibleForDaemon bool `json:"eligible_for_daemon"`
	} `json:"capacity"`
	CreatedAt string `json:"created_at"`
	UpdatedAt string `json:"updated_at"`
}

type ServerList struct {
	Data []Server        `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *ServerList) setRaw(raw json.RawMessage) { response.Raw = raw }

type ServerEnvelope struct {
	Data Server          `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *ServerEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

type Capability struct {
	Name         string   `json:"name"`
	Enabled      bool     `json:"enabled"`
	Reason       *string  `json:"reason"`
	Dependencies []string `json:"dependencies"`
}

type CapabilityList struct {
	Data []Capability    `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *CapabilityList) setRaw(raw json.RawMessage) { response.Raw = raw }

type Operation struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Status   string `json:"status"`
	Resource *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Result    map[string]any `json:"result"`
	ErrorCode *string        `json:"error_code"`
	Retryable bool           `json:"retryable"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

type OperationEnvelope struct {
	Data       Operation       `json:"data"`
	Meta       map[string]any  `json:"meta"`
	Raw        json.RawMessage `json:"-"`
	RetryAfter string          `json:"-"`
}

func (response *OperationEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

func (response *OperationEnvelope) setResponseHeaders(headers http.Header) {
	response.RetryAfter = headers.Get("Retry-After")
}

type OperationList struct {
	Data []Operation     `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *OperationList) setRaw(raw json.RawMessage) { response.Raw = raw }

type DeviceAuthorization struct {
	Data struct {
		DeviceCode      string `json:"device_code"`
		VerificationURL string `json:"verification_url"`
		ExpiresAt       string `json:"expires_at"`
		IntervalSeconds int    `json:"interval_seconds"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

type DeviceAuthorizationStatus struct {
	Data struct {
		Status      string `json:"status"`
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

type Ticket struct {
	Data struct {
		GatewayURL string   `json:"gateway_url"`
		Ticket     string   `json:"ticket"`
		ExpiresIn  int      `json:"expires_in"`
		Protocol   int      `json:"terminal_protocol"`
		Features   []string `json:"features"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

type UploadResponse struct {
	OK   bool   `json:"ok"`
	Path string `json:"path"`
}

func (c *Client) CreateDeviceAuthorization(ctx context.Context, scopes []string, lifetime string) (DeviceAuthorization, error) {
	var result DeviceAuthorization
	err := c.doJSON(ctx, http.MethodPost, "/device-authorizations", map[string]any{
		"name":     "daemons CLI",
		"scopes":   scopes,
		"lifetime": lifetime,
	}, false, "", false, &result)
	return result, err
}

func (c *Client) PollDeviceAuthorization(ctx context.Context, code string) (DeviceAuthorizationStatus, error) {
	var result DeviceAuthorizationStatus
	err := c.doJSON(ctx, http.MethodGet, "/device-authorizations/"+url.PathEscape(code), nil, false, "", false, &result)
	return result, err
}

func (c *Client) Me(ctx context.Context) (Me, error) {
	var result Me
	err := c.doJSON(ctx, http.MethodGet, "/me", nil, true, "", false, &result)
	return result, err
}

func (c *Client) Logout(ctx context.Context, idempotencyKey string) error {
	return c.doJSON(ctx, http.MethodDelete, "/tokens/current", nil, true, idempotencyKey, true, nil)
}

func (c *Client) Capabilities(ctx context.Context) (CapabilityList, error) {
	var result CapabilityList
	err := c.doJSON(ctx, http.MethodGet, "/capabilities", nil, true, "", false, &result)
	if err == nil {
		for _, capability := range result.Data {
			if capability.Name == "" {
				return CapabilityList{}, invalidResponse()
			}
		}
	}
	return result, err
}

func (c *Client) ListServers(ctx context.Context) (ServerList, error) {
	var result ServerList
	err := c.doJSON(ctx, http.MethodGet, "/servers", nil, true, "", false, &result)
	if err == nil {
		for _, server := range result.Data {
			if server.ID == "" || server.Name == "" || server.Status == "" {
				return ServerList{}, invalidResponse()
			}
		}
	}
	return result, err
}

func (c *Client) ShowServer(ctx context.Context, serverID string) (ServerEnvelope, error) {
	var result ServerEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/servers/"+url.PathEscape(serverID), nil, true, "", false, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Name == "" || result.Data.Status == "") {
		return ServerEnvelope{}, invalidResponse()
	}
	return result, err
}

func (c *Client) ListDaemons(ctx context.Context) (DaemonList, error) {
	var result DaemonList
	err := c.doJSON(ctx, http.MethodGet, "/daemons", nil, true, "", false, &result)
	return result, err
}

func (c *Client) ShowDaemon(ctx context.Context, daemonID string) (DaemonEnvelope, error) {
	var result DaemonEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/daemons/"+url.PathEscape(daemonID), nil, true, "", false, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Name == "" || result.Data.Status == "") {
		return DaemonEnvelope{}, invalidResponse()
	}
	return result, err
}

func (c *Client) LifecycleDaemon(ctx context.Context, daemonID, action, idempotencyKey string) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	var result OperationEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/"+action, nil, true, idempotencyKey, true, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Type == "" || result.Data.Status == "") {
		return OperationEnvelope{}, invalidMutationResponse()
	}
	return result, err
}

func (c *Client) SpawnDaemon(ctx context.Context, spawn SpawnRequest, idempotencyKey string) (DaemonSpawnEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return DaemonSpawnEnvelope{}, err
	}
	body := map[string]any{
		"server_id": spawn.ServerID,
		"name":      spawn.Name,
	}
	if spawn.PrimaryAgent != "" {
		body["primary_agent"] = spawn.PrimaryAgent
	}
	if spawn.DiskQuotaGB > 0 {
		body["disk_quota_gb"] = spawn.DiskQuotaGB
	}
	var result DaemonSpawnEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons", body, true, idempotencyKey, true, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Name == "" || result.Meta.Operation.ID == "" || result.Meta.Operation.Status == "") {
		return DaemonSpawnEnvelope{}, invalidMutationResponse()
	}
	return result, err
}

// DestroyDaemon sends the conditional delete. The caller supplies the ETag
// captured from ShowDaemon; an empty ETag sends no If-Match and lets the
// server reject the unconditional request.
func (c *Client) DestroyDaemon(ctx context.Context, daemonID, etag, idempotencyKey string) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	headers := http.Header{}
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	var result OperationEnvelope
	err := c.doJSONWithHeaders(ctx, http.MethodDelete, "/daemons/"+url.PathEscape(daemonID), nil, true, idempotencyKey, true, headers, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Type == "" || result.Data.Status == "") {
		return OperationEnvelope{}, invalidMutationResponse()
	}
	return result, err
}

func (c *Client) ListOperations(ctx context.Context, limit int) (OperationList, error) {
	requestPath := "/operations"
	if limit > 0 {
		requestPath += "?limit=" + strconv.Itoa(limit)
	}
	var result OperationList
	err := c.doJSON(ctx, http.MethodGet, requestPath, nil, true, "", false, &result)
	if err == nil {
		for _, operation := range result.Data {
			if operation.ID == "" || operation.Type == "" || operation.Status == "" {
				return OperationList{}, invalidResponse()
			}
		}
	}
	return result, err
}

// ResolveServer accepts a server UUID or exact name. Names are matched
// exactly against the account's server list; there is no prefix matching.
func (c *Client) ResolveServer(ctx context.Context, value string) (Server, error) {
	servers, err := c.ListServers(ctx)
	if err != nil {
		return Server{}, err
	}
	for _, server := range servers.Data {
		if server.ID == value || server.Name == value {
			return server, nil
		}
	}
	return Server{}, &errs.APIError{Status: 404, Code: "not_found", Detail: "The server was not found."}
}

func (c *Client) ShowOperation(ctx context.Context, operationID string) (OperationEnvelope, error) {
	var result OperationEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/operations/"+url.PathEscape(operationID), nil, true, "", false, &result)
	if err == nil && (result.Data.ID == "" || result.Data.Type == "" || result.Data.Status == "") {
		return OperationEnvelope{}, invalidResponse()
	}
	return result, err
}

func (c *Client) ResolveDaemon(ctx context.Context, value string) (Daemon, error) {
	daemons, err := c.ListDaemons(ctx)
	if err != nil {
		return Daemon{}, err
	}
	for _, daemon := range daemons.Data {
		if daemon.ID == value || daemon.Name == value {
			return daemon, nil
		}
	}

	return Daemon{}, &errs.APIError{Status: 404, Code: "not_found", Detail: "The daemon was not found."}
}

func (c *Client) MintTicket(ctx context.Context, daemonID, session string, cols, rows int) (Ticket, error) {
	if err := c.Preflight(ctx); err != nil {
		return Ticket{}, err
	}
	var result Ticket
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/terminal-tickets", map[string]any{
		"session":     session,
		"cols":        cols,
		"rows":        rows,
		"attach_mode": "create_or_attach",
	}, true, legacyIdempotencyKey(), true, &result)
	return result, err
}

func (c *Client) Upload(ctx context.Context, daemonID, filename string, file *os.File) (UploadResponse, error) {
	if err := c.Preflight(ctx); err != nil {
		return UploadResponse{}, err
	}
	return c.upload(ctx, daemonID, filename, file)
}

func invalidResponse() error {
	return errs.New("invalid_response", "The Control Plane API returned an invalid resource document.", 1)
}

func invalidMutationResponse() error {
	return errs.New("outcome_unknown", "The Control Plane accepted the mutation but returned an invalid operation document. Reconcile the resource before retrying with the same idempotency key.", 8)
}

func IsAPIError(err error, code string) bool {
	var apiError *errs.APIError
	return errors.As(err, &apiError) && apiError.Code == code
}
