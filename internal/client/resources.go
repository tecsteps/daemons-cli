package client

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	} `json:"-"`
	Size      string `json:"size,omitempty"`
	Variant   string `json:"variant,omitempty"`
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
	ServerID        string
	Name            string
	PrimaryAgent    string
	DiskQuotaGB     int
	Size            string
	Variant         string
	Source          string
	AssignedUserID  string
	CreationTeamID  string
	TeamID          string
	AcceptedOfferID string
}

type Server struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Status   string `json:"status"`
	Region   string `json:"region"`
	Capacity struct {
		Cores             WireInt `json:"cores"`
		MemoryGB          WireInt `json:"memory_gb"`
		DiskGB            WireInt `json:"disk_gb"`
		DaemonCount       WireInt `json:"daemon_count"`
		EligibleForDaemon bool    `json:"eligible_for_daemon"`
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
	UUID       string  `json:"uuid,omitempty"`
	State      string  `json:"state,omitempty"`
	Phase      string  `json:"phase,omitempty"`
	DaemonID   string  `json:"daemon_id,omitempty"`
	ReasonCode *string `json:"reason_code,omitempty"`
	ID         string  `json:"id"`
	Type       string  `json:"type"`
	Status     string  `json:"status"`
	Resource   *struct {
		Type string `json:"type"`
		ID   string `json:"id"`
	} `json:"resource"`
	Result    map[string]any `json:"result"`
	ErrorCode *string        `json:"error_code"`
	Retryable bool           `json:"retryable"`
	CreatedAt string         `json:"created_at"`
	UpdatedAt string         `json:"updated_at"`
}

// UnmarshalJSON accepts both the lifecycle projection and older task operations.
// Raw envelopes retain the exact wire document for JSON output.
func (operation *Operation) UnmarshalJSON(raw []byte) error {
	type wire Operation
	var value wire
	if err := json.Unmarshal(raw, &value); err != nil {
		return err
	}
	*operation = Operation(value)
	if operation.ID == "" {
		operation.ID = operation.UUID
	}
	if operation.State != "" {
		operation.Status = operation.State
	}
	if operation.ReasonCode != nil {
		operation.ErrorCode = operation.ReasonCode
	}
	return nil
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
		DeviceCode      string  `json:"device_code"`
		VerificationURL string  `json:"verification_url"`
		ExpiresAt       string  `json:"expires_at"`
		IntervalSeconds WireInt `json:"interval_seconds"`
	} `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *DeviceAuthorization) setRaw(raw json.RawMessage) { response.Raw = raw }

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
		ExpiresIn  WireInt  `json:"expires_in"`
		Protocol   WireInt  `json:"terminal_protocol"`
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
	if err == nil {
		switch {
		case result.Data.DeviceCode == "":
			return DeviceAuthorization{}, invalidResponse("data.device_code")
		case result.Data.VerificationURL == "":
			return DeviceAuthorization{}, invalidResponse("data.verification_url")
		}
	}
	return result, err
}

func (c *Client) PollDeviceAuthorization(ctx context.Context, code string) (DeviceAuthorizationStatus, error) {
	var result DeviceAuthorizationStatus
	err := c.doJSON(ctx, http.MethodGet, "/device-authorizations/"+url.PathEscape(code), nil, false, "", false, &result)
	if err == nil && result.Data.Status == "" {
		return DeviceAuthorizationStatus{}, invalidResponse("data.status")
	}
	return result, err
}

func (c *Client) Me(ctx context.Context) (Me, error) {
	var result Me
	err := c.doJSON(ctx, http.MethodGet, "/me", nil, true, "", false, &result)
	if err == nil {
		switch {
		case result.Data.Account.ID == "":
			return Me{}, invalidResponse("data.account.id")
		case result.Data.Account.Email == "":
			return Me{}, invalidResponse("data.account.email")
		case result.Data.Token.ID == "":
			return Me{}, invalidResponse("data.token.id")
		}
	}
	return result, err
}

func (c *Client) Logout(ctx context.Context, idempotencyKey string) error {
	return c.doJSON(ctx, http.MethodDelete, "/tokens/current", nil, true, idempotencyKey, true, nil)
}

func (c *Client) Capabilities(ctx context.Context) (CapabilityList, error) {
	var result CapabilityList
	err := c.doJSON(ctx, http.MethodGet, "/capabilities", nil, true, "", false, &result)
	if err == nil {
		for index, capability := range result.Data {
			if capability.Name == "" {
				return CapabilityList{}, invalidResponse(fmt.Sprintf("data[%d].name", index))
			}
		}
	}
	return result, err
}

func (c *Client) ListServers(ctx context.Context) (ServerList, error) {
	var result ServerList
	err := c.doJSON(ctx, http.MethodGet, "/servers", nil, true, "", false, &result)
	if err == nil {
		for index, server := range result.Data {
			if field := missingServerField(server); field != "" {
				return ServerList{}, invalidResponse(fmt.Sprintf("data[%d].%s", index, field))
			}
		}
	}
	return result, err
}

func (c *Client) ShowServer(ctx context.Context, serverID string) (ServerEnvelope, error) {
	var result ServerEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/servers/"+url.PathEscape(serverID), nil, true, "", false, &result)
	if err == nil {
		if field := missingServerField(result.Data); field != "" {
			return ServerEnvelope{}, invalidResponse("data." + field)
		}
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
	if err == nil {
		if field := missingDaemonField(result.Data); field != "" {
			return DaemonEnvelope{}, invalidResponse("data." + field)
		}
	}
	return result, err
}

func (c *Client) LifecycleDaemon(ctx context.Context, daemonID, action, idempotencyKey string) (OperationEnvelope, error) {
	return c.LifecycleDaemonWithOptions(ctx, daemonID, action, "", idempotencyKey, nil)
}

func (c *Client) LifecycleDaemonWithOptions(ctx context.Context, daemonID, action, etag, idempotencyKey string, body map[string]any) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	var result OperationEnvelope
	headers := http.Header{}
	if etag != "" {
		headers.Set("If-Match", etag)
	}
	err := c.doJSONWithHeaders(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/"+action, body, true, idempotencyKey, true, headers, &result)
	if err == nil {
		if result.Data.Type == "" && result.Data.UUID != "" {
			result.Data.Type = "daemon." + action
		}
		if field := missingOperationField(result.Data); field != "" {
			return OperationEnvelope{}, invalidMutationResponse("data." + field)
		}
	}
	return result, err
}

func (c *Client) RenameDaemon(ctx context.Context, daemonID, name, etag, key string) (DaemonEnvelope, error) {
	var result DaemonEnvelope
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	err := c.doJSONWithHeaders(ctx, http.MethodPatch, "/daemons/"+url.PathEscape(daemonID), map[string]any{"name": name}, true, key, true, http.Header{"If-Match": []string{etag}}, &result)
	if err == nil {
		if field := missingDaemonField(result.Data); field != "" {
			return result, invalidMutationResponse("data." + field)
		}
	}
	return result, err
}

func (c *Client) MutateOperation(ctx context.Context, id, action, key string) (OperationEnvelope, error) {
	var result OperationEnvelope
	if action != "cancel" && action != "retry" {
		return result, errs.New("usage_error", "Unsupported operation action.", 2)
	}
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	err := c.doJSON(ctx, http.MethodPost, "/operations/"+url.PathEscape(id)+"/"+action, nil, true, key, true, &result)
	if err == nil {
		if field := missingOperationField(result.Data); field != "" {
			return result, invalidMutationResponse("data." + field)
		}
	}
	return result, err
}

type BulkOutcome struct {
	DaemonID    string  `json:"daemon_id"`
	OperationID *string `json:"operation_id"`
	Status      string  `json:"status"`
	Code        *string `json:"code"`
}

type BulkEnvelope struct {
	Data struct {
		Outcomes []BulkOutcome `json:"outcomes"`
	} `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (response *BulkEnvelope) setRaw(raw json.RawMessage) { response.Raw = raw }

func (c *Client) BulkDaemons(ctx context.Context, action string, ids []string, key string) (BulkEnvelope, error) {
	var result BulkEnvelope
	// The published bulk destroy route does not enforce the frozen confirmation
	// or revision-set precondition. Do not expose that bypass in this client.
	if action != "stop" {
		return result, errs.New("confirmation_unavailable", "Bulk deletion is unavailable until the API supports confirmation bound to the complete revision set. Delete each workspace with browser confirmation.", 6)
	}
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	err := c.doJSON(ctx, http.MethodPost, "/daemons/bulk/stop", map[string]any{"daemon_ids": ids}, true, key, true, &result)
	if err == nil {
		seen := map[string]bool{}
		for _, outcome := range result.Data.Outcomes {
			if seen[outcome.DaemonID] || outcome.DaemonID == "" || (outcome.Status != "accepted" && outcome.Status != "failed") || (outcome.Status == "accepted" && (outcome.OperationID == nil || *outcome.OperationID == "")) {
				return result, invalidMutationResponse("data.outcomes")
			}
			seen[outcome.DaemonID] = true
		}
		if len(seen) != len(ids) {
			return result, invalidMutationResponse("data.outcomes")
		}
		for _, id := range ids {
			if !seen[id] {
				return result, invalidMutationResponse("data.outcomes")
			}
		}
	}
	return result, err
}

func (c *Client) SpawnDaemon(ctx context.Context, spawn SpawnRequest, idempotencyKey string) (DaemonSpawnEnvelope, error) {
	if spawn.ServerID != "" || spawn.DiskQuotaGB != 0 {
		return DaemonSpawnEnvelope{}, errs.New("server_selection_removed", "Server selection and disk quotas are no longer supported.", 2)
	}
	if err := c.Preflight(ctx); err != nil {
		return DaemonSpawnEnvelope{}, err
	}
	body := map[string]any{"name": spawn.Name, "size": spawn.Size, "variant": spawn.Variant,
		"source": spawn.Source, "assigned_user_id": spawn.AssignedUserID, "creation_team_id": spawn.CreationTeamID,
		"accepted_offer_id": nil}
	if spawn.TeamID != "" {
		body["team_id"] = spawn.TeamID
	}
	if spawn.AcceptedOfferID != "" {
		body["accepted_offer_id"] = spawn.AcceptedOfferID
	}
	if spawn.PrimaryAgent != "" {
		body["primary_agent"] = spawn.PrimaryAgent
	}
	if spawn.DiskQuotaGB > 0 {
		body["disk_quota_gb"] = spawn.DiskQuotaGB
	}
	var result DaemonSpawnEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons", body, true, idempotencyKey, true, &result)
	if err == nil {
		if field := missingDaemonField(result.Data); field != "" {
			return DaemonSpawnEnvelope{}, invalidMutationResponse("data." + field)
		}
		if result.Meta.Operation.ID == "" {
			return DaemonSpawnEnvelope{}, invalidMutationResponse("meta.operation.uuid")
		}
		if result.Meta.Operation.Type == "" {
			result.Meta.Operation.Type = "daemon.create"
		}
		if result.Meta.Operation.Status == "" {
			result.Meta.Operation.Status = "queued"
		}
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
	if err == nil {
		if field := missingOperationField(result.Data); field != "" {
			return OperationEnvelope{}, invalidMutationResponse("data." + field)
		}
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
		for index, operation := range result.Data {
			if field := missingOperationField(operation); field != "" {
				return OperationList{}, invalidResponse(fmt.Sprintf("data[%d].%s", index, field))
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
	if err == nil {
		if field := missingOperationField(result.Data); field != "" {
			return OperationEnvelope{}, invalidResponse("data." + field)
		}
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
	if err == nil {
		switch {
		case result.Data.GatewayURL == "":
			return Ticket{}, invalidMutationResponse("data.gateway_url")
		case result.Data.Ticket == "":
			return Ticket{}, invalidMutationResponse("data.ticket")
		case result.Data.Protocol == 0:
			return Ticket{}, invalidMutationResponse("data.terminal_protocol")
		}
	}
	return result, err
}

func (c *Client) Upload(ctx context.Context, daemonID, filename string, file *os.File) (UploadResponse, error) {
	if err := c.Preflight(ctx); err != nil {
		return UploadResponse{}, err
	}
	c.preflightMu.Lock()
	v2 := c.accessV2
	c.preflightMu.Unlock()
	if v2 {
		return c.uploadAccess(ctx, daemonID, newAccessOperationID(), DefaultWorkspacePaths(), filename, file)
	}
	return c.upload(ctx, daemonID, filename, file)
}

func invalidResponse(field string) error {
	return errs.New("invalid_response", unexpectedShapeMessage(field), 1)
}

func invalidMutationResponse(field string) error {
	return errs.New("outcome_unknown", "The mutation may have been accepted, but the Control Plane API response shape was unexpected at field "+field+". Reconcile the resource before retrying with the same idempotency key.", 8)
}

func unexpectedShapeMessage(field string) string {
	return "The Control Plane API response shape was unexpected at field " + field + "."
}

func missingServerField(server Server) string {
	switch {
	case server.ID == "":
		return "id"
	case server.Name == "":
		return "name"
	case server.Status == "":
		return "status"
	default:
		return ""
	}
}

func missingDaemonField(daemon Daemon) string {
	switch {
	case daemon.ID == "":
		return "id"
	case daemon.Name == "":
		return "name"
	case daemon.Status == "":
		return "status"
	default:
		return ""
	}
}

func missingOperationField(operation Operation) string {
	switch {
	case operation.ID == "":
		return "id"
	case operation.Type == "":
		return "type"
	case operation.Status == "":
		return "status"
	default:
		return ""
	}
}

func IsAPIError(err error, code string) bool {
	var apiError *errs.APIError
	return errors.As(err, &apiError) && apiError.Code == code
}
