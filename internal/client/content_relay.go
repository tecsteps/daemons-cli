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

// uploadAccess streams the selector prelude and file without a central multipart
// request or a replayable request body. An ambiguous result is never retried.
func (c *Client) uploadAccess(ctx context.Context, daemonID, filename string, file *os.File) (UploadResponse, error) {
	var result UploadResponse
	if filename == "" || filename == "." || filename == ".." || strings.ContainsAny(filename, "/\\\x00\r\n") {
		return result, errs.New("unsafe_workspace_path", "The upload filename is invalid.", 2)
	}
	stat, err := file.Stat()
	if err != nil || !stat.Mode().IsRegular() || stat.Size() > 1<<30 {
		return result, errs.New("upload_limit", "Upload requires a regular file no larger than 1 GiB.", 2)
	}
	selector, err := json.Marshal(map[string]string{"path": "uploads/" + filename})
	if err != nil || len(selector) > 16384 {
		return result, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	prelude := make([]byte, 4+len(selector))
	binary.BigEndian.PutUint32(prelude, uint32(len(selector)))
	copy(prelude[4:], selector)
	var output boundedContentJSON
	if err := c.AccessContent(ctx, daemonID, newAccessOperationID(), "files.upload", io.MultiReader(bytes.NewReader(prelude), file), &output); err != nil {
		return result, err
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		return result, invalidMutationResponse("upload receipt")
	}
	return result, nil
}

type boundedContentJSON struct{ buffer bytes.Buffer }

func (b *boundedContentJSON) Bytes() []byte { return b.buffer.Bytes() }

func (b *boundedContentJSON) Write(value []byte) (int, error) {
	if b.buffer.Len()+len(value) > maximumJSONResponse {
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

type AccessTicket struct {
	Data struct {
		Ticket      string  `json:"ticket"`
		Version     int     `json:"ticket_version"`
		ExpiresIn   WireInt `json:"expires_in"`
		Method      string  `json:"method"`
		GatewayPath string  `json:"gateway_path"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

// MintAccessTicket sends only public identifiers and a closed action name.
func (c *Client) MintAccessTicket(ctx context.Context, daemonID, operationID, action string) (AccessTicket, error) {
	var result AccessTicket
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/access-tickets", map[string]string{
		"action": action, "operation_uuid": operationID,
	}, true, "", true, &result)
	if err != nil {
		return result, err
	}
	suffix := map[string]string{"files.read": "/files/query", "files.download": "/files/downloads", "files.upload": "/files/uploads/" + operationID, "logs.read": "/logs/query", "logs.download": "/logs/downloads"}[action]
	method := http.MethodPost
	if action == "files.upload" {
		method = http.MethodPut
	}
	if suffix == "" || result.Data.Version != 2 || result.Data.ExpiresIn < 1 || result.Data.ExpiresIn > 30 || result.Data.Method != method || result.Data.GatewayPath != "/v1/workspaces/"+daemonID+suffix {
		return AccessTicket{}, invalidResponse("data.access_ticket")
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
// authority. Tickets remain opaque and are never placed in a URL.
func (c *Client) ValidateGatewayURL(value string) error {
	u, err := url.Parse(value)
	if err != nil || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.RawPath != "" {
		return unsafeGateway()
	}
	scheme := u.Scheme
	if scheme == "wss" {
		scheme = "https"
	}
	if scheme == "ws" {
		scheme = "http"
	}
	if scheme != c.baseURL.Scheme || !strings.EqualFold(u.Host, c.baseURL.Host) || !strings.HasPrefix(u.Path, "/") || strings.Contains(u.Path, "\\") {
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
	request.Header.Set("Content-Type", "application/octet-stream")
	request.Header.Set("Accept", "application/octet-stream, application/json")
	response, err := c.GatewayHTTPClient().Do(request)
	if err != nil {
		return errs.New("relay_outcome_unknown", "The content transfer was interrupted. Obtain a fresh receipt ticket before retrying a write.", 8)
	}
	defer response.Body.Close()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		// Upstream errors may contain content. Never decode or print that body.
		return errs.New("relay_refused", "The gateway refused the content transfer.", 5)
	}
	if _, err := io.CopyBuffer(destination, response.Body, make([]byte, 32*1024)); err != nil {
		return errs.New("relay_partial", "The content transfer is incomplete; do not use the partial result.", 8)
	}
	return nil
}
