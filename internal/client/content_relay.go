package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

// UploadRecoverable reports whether this Control Plane serves uploads through
// workspace access, where an operation identity makes an ambiguous outcome
// resolvable by receipt. Callers stage an identity only when it is true.
func (c *Client) UploadRecoverable(ctx context.Context) (bool, error) {
	if err := c.Preflight(ctx); err != nil {
		return false, err
	}
	c.preflightMu.Lock()
	defer c.preflightMu.Unlock()
	return c.accessV2, nil
}

// NewUploadOperationID mints the operation identity a caller must persist
// before an upload, so an ambiguous outcome stays resolvable by receipt.
func NewUploadOperationID() string { return newAccessOperationID() }

// UploadOperation streams one file under a caller-supplied operation identity.
// The identity is deliberately an input: the caller records it locally before
// the request so an interrupted transfer can be resolved without replaying it.
func (c *Client) UploadOperation(ctx context.Context, daemonID, operationID string, paths WorkspacePaths, filename string, file *os.File) (UploadResponse, error) {
	if !payloadUUID.MatchString(operationID) {
		return UploadResponse{}, errs.New("usage_error", "An upload operation UUID is required.", 2)
	}
	if err := c.Preflight(ctx); err != nil {
		return UploadResponse{}, err
	}
	c.preflightMu.Lock()
	v2 := c.accessV2
	c.preflightMu.Unlock()
	if !v2 {
		// A v1 Control Plane has no receipt to resolve, so the operation
		// identity is not recorded and the legacy upload runs unchanged.
		return c.upload(ctx, daemonID, filename, file)
	}
	return c.uploadAccess(ctx, daemonID, operationID, paths, filename, file)
}

// uploadAccess streams the selector prelude and file without a central multipart
// request or a replayable request body. An ambiguous result is never retried.
func (c *Client) uploadAccess(ctx context.Context, daemonID, operationID string, paths WorkspacePaths, filename string, file *os.File) (UploadResponse, error) {
	var result UploadResponse
	selectorPath, err := paths.UploadSelector(filename)
	if err != nil {
		return result, err
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 1<<30 {
		return result, errs.New("upload_limit", "Upload requires a regular file no larger than 1 GiB.", 2)
	}
	selector, err := json.Marshal(map[string]string{"path": selectorPath})
	if err != nil || len(selector) > 16384 {
		return result, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	prelude := make([]byte, 4+len(selector))
	binary.BigEndian.PutUint32(prelude, uint32(len(selector)))
	copy(prelude[4:], selector)
	output := boundedContentJSON{maximum: 32768}
	if err := c.AccessContent(ctx, daemonID, operationID, "files.upload", io.MultiReader(bytes.NewReader(prelude), file), &output); err != nil {
		return result, uploadOutcomeError(operationID, err)
	}
	receipt, err := decodeUploadReceiptPath(output.Bytes(), true)
	if err != nil || receipt.Status != "applied" || receipt.Bytes != stat.Size() {
		return result, uploadOutcomeError(operationID, invalidMutationResponse("upload receipt"))
	}
	return UploadResponse{OK: true, Path: receipt.Path}, nil
}

func uploadOutcomeError(operationID string, err error) error {
	if errs.ExitCode(err) != 8 {
		return err
	}
	return errs.New(errs.Code(err), fmt.Sprintf("Upload outcome is unknown. Check operation %s with: daemons files receipt DAEMON %s. Do not replay the upload automatically.", operationID, operationID), 8)
}

type boundedContentJSON struct {
	buffer  bytes.Buffer
	maximum int
}

// DownloadFile keeps the path in the guest stream and copies bytes with bounded memory.
func (c *Client) DownloadFile(ctx context.Context, daemonID, workspacePath string, destination io.Writer) error {
	selector, err := json.Marshal(map[string]string{"path": workspacePath})
	if err != nil || len(selector) > 16384 {
		return errs.New("relay_limit", "The download selector is too large.", 2)
	}
	return c.AccessContent(ctx, daemonID, newAccessOperationID(), "files.download", bytes.NewReader(selector), destination)
}

func (b *boundedContentJSON) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedContentJSON) Write(value []byte) (int, error) {
	limit := b.maximum
	if limit == 0 {
		limit = maximumJSONResponse
	}
	if b.buffer.Len()+len(value) > limit {
		return 0, errs.New("relay_limit", "The guest response exceeded its limit.", 8)
	}
	return b.buffer.Write(value)
}
func newAccessOperationID() string {
	var value [16]byte
	if _, err := rand.Read(value[:]); err != nil {
		panic("random source unavailable")
	}
	value[6] = (value[6] & 15) | 64
	value[8] = (value[8] & 63) | 128
	return fmt.Sprintf("%x-%x-%x-%x-%x", value[:4], value[4:6], value[6:8], value[8:10], value[10:])
}

// ExitRevisionConflict marks an expected-revision mismatch. It is deliberately
// distinct from denial (5) and from an unknown outcome (8): the request was
// understood and refused because the workspace moved on.
const ExitRevisionConflict = 9

type AccessTicket struct {
	Data struct {
		Ticket      string             `json:"ticket"`
		Version     int                `json:"ticket_version"`
		ExpiresIn   WireInt            `json:"expires_in"`
		Method      string             `json:"method"`
		GatewayPath string             `json:"gateway_path"`
		Target      LocalPayloadTarget `json:"target"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

// MintAccessTicket sends only public identifiers and a closed action name.
func (c *Client) MintAccessTicket(ctx context.Context, daemonID, operationID, action string) (AccessTicket, error) {
	return c.mintAccessTicket(ctx, daemonID, operationID, action, "")
}

func (c *Client) mintAccessTicket(ctx context.Context, daemonID, operationID, action, taskID string) (AccessTicket, error) {
	var result AccessTicket
	metadata := map[string]string{"action": action, "operation_uuid": operationID}
	if action == "tasks.submit" || action == "tasks.cancel" {
		if !payloadUUID.MatchString(taskID) || !payloadUUID.MatchString(operationID) {
			return result, invalidResponse("task identity")
		}
		metadata["task_uuid"] = taskID
	} else if taskID != "" {
		return result, invalidResponse("task action")
	}
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/access-tickets", metadata, true, "", true, &result)
	if err != nil {
		return result, err
	}
	suffix := map[string]string{"files.read": "/files/query", "files.download": "/files/downloads", "files.upload": "/files/uploads/" + operationID, "logs.read": "/logs/query", "logs.download": "/logs/downloads", "local_payload.put": "/local-payloads/" + operationID, "local_payload.receipt": "/local-payloads/" + operationID, "tasks.read": "/tasks/query"}[action]
	method := http.MethodPost
	if action == "tasks.cancel" {
		suffix = "/tasks/" + taskID + "/cancel"
	}
	if action == "tasks.submit" {
		suffix = "/tasks/" + taskID
		method = http.MethodPut
	}
	if action == "files.upload" || action == "local_payload.put" {
		method = http.MethodPut
	}
	if action == "local_payload.receipt" {
		method = http.MethodGet
	}
	if suffix == "" || result.Data.Version != 2 || result.Data.ExpiresIn < 1 || result.Data.ExpiresIn > 30 || result.Data.Method != method || result.Data.GatewayPath != "/v1/workspaces/"+daemonID+suffix {
		return AccessTicket{}, invalidResponse("data.access_ticket")
	}
	if (strings.HasPrefix(action, "local_payload.") || action == "tasks.submit") && (!result.Data.Target.valid(daemonID) || !payloadUUID.MatchString(operationID)) {
		return AccessTicket{}, invalidResponse("data.target")
	}
	return result, nil
}

// AccessContent obtains one v2 ticket, then streams once to the fixed edge path.
func (c *Client) AccessContent(ctx context.Context, daemonID, operationID, action string, source io.Reader, destination io.Writer) error {
	ticket, err := c.MintAccessTicket(ctx, daemonID, operationID, action)
	if err != nil {
		return err
	}
	u := *c.baseURL
	u.Path = ticket.Data.GatewayPath
	u.RawPath = ""
	return c.relayContent(ctx, ticket.Data.Method, u.String(), ticket.Data.Ticket, source, destination)
}

// ValidateGatewayURL binds a ticket destination to the configured control-plane
// authority. Tickets remain opaque and are never placed in a URL. SSH tickets
// may use the DNS-only host ssh.daemons.run:2222; content relay stays on the
// API host.
func (c *Client) ValidateGatewayURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return unsafeGateway()
	}
	if !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "\\") {
		return unsafeGateway()
	}
	if u.Scheme == "wss" && strings.EqualFold(u.Host, sshGatewayAuthority()) && u.Path == sshGatewayPath {
		return nil
	}
	scheme := u.Scheme
	if scheme == "wss" {
		scheme = "https"
	}
	if scheme == "ws" {
		scheme = "http"
	}
	if scheme != c.baseURL.Scheme || !strings.EqualFold(u.Host, c.baseURL.Host) {
		return unsafeGateway()
	}
	return nil
}

func unsafeGateway() error {
	return errs.New("unsafe_gateway_url", "The gateway destination is not approved for this Control Plane.", 10)
}

// GatewayHTTPClient preserves configured TLS trust but never cookies, redirects,
// or a global response timeout for a lease-governed stream.
func (c *Client) GatewayHTTPClient() *http.Client {
	return &http.Client{Transport: c.http.Transport, CheckRedirect: RejectGatewayRedirect}
}

func RejectGatewayRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// RelayContent transfers directly to the admitted gateway, not the control-plane
// API. The caller supplies a fresh single-use ticket and owns the input stream.
// An uncertain write is never retried; recover through a fresh receipt ticket.
func (c *Client) RelayContent(ctx context.Context, gateway, ticket string, source io.Reader, destination io.Writer) error {
	return c.relayContent(ctx, http.MethodPost, gateway, ticket, source, destination)
}

func (c *Client) relayContent(ctx context.Context, method, gateway, ticket string, source io.Reader, destination io.Writer) error {
	return c.relayContentType(ctx, method, gateway, ticket, "application/octet-stream", source, destination)
}

func (c *Client) relayContentType(ctx context.Context, method, gateway, ticket, contentType string, source io.Reader, destination io.Writer) error {
	if err := c.ValidateGatewayURL(gateway); err != nil {
		return err
	}
	u, _ := url.Parse(gateway)
	if (u.Scheme != "https" && u.Scheme != "http") || !strings.HasPrefix(u.Path, "/v1/workspaces/") || ticket == "" || len(ticket) > 4096 || strings.ContainsAny(ticket, "\r\n \t") {
		return unsafeGateway()
	}
	request, err := http.NewRequestWithContext(ctx, method, gateway, source)
	if err != nil {
		return unsafeGateway()
	}
	request.GetBody = nil
	request.Header.Set("Authorization", "DaemonsTicket "+ticket)
	request.Header.Set("Content-Type", contentType)
	request.Header.Set("Accept", "application/octet-stream, application/json")
	response, err := c.GatewayHTTPClient().Do(request)
	if err != nil {
		return errs.New("relay_outcome_unknown", "The content transfer was interrupted. Obtain a fresh receipt ticket before retrying a write.", 8)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusConflict {
		// The guest reports revision_conflict, payload_conflict and
		// stale_generation as 409. The caller must re-read the current revision
		// and decide; the CLI never resolves a conflict by retrying.
		return errs.New("revision_conflict", "The workspace changed since the expected revision. Re-read the current state before retrying.", ExitRevisionConflict)
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Upstream errors may contain content. Never decode or print that body.
		return errs.New("relay_refused", "The gateway refused the content transfer.", 5)
	}
	if _, err := io.CopyBuffer(destination, response.Body, make([]byte, 32*1024)); err != nil {
		return errs.New("relay_partial", "The content transfer is incomplete; do not use the partial result.", 8)
	}
	return nil
}
