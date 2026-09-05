package client

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
)

// SSHAccess is deliberately a public-only export. It never contains a ticket
// or private key material.
type SSHAccess struct {
	Enabled            bool     `json:"enabled"`
	Reconciled         bool     `json:"reconciled"`
	HostKey            string   `json:"host_key"`
	HostKeyFingerprint string   `json:"host_key_fingerprint"`
	Keys               []SSHKey `json:"keys"`
}
type SSHKey struct {
	ID          string `json:"id"`
	Fingerprint string `json:"fingerprint"`
	PublicKey   string `json:"public_key"`
}
type SSHEnvelope struct {
	Data SSHAccess       `json:"data"`
	Meta map[string]any  `json:"meta"`
	Raw  json.RawMessage `json:"-"`
}

func (r *SSHEnvelope) setRaw(b json.RawMessage) { r.Raw = b }

type SSHTicket struct {
	Data struct {
		Ticket     string  `json:"ticket"`
		ExpiresIn  WireInt `json:"expires_in"`
		GatewayURL string  `json:"gateway_url"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

func (c *Client) SSH(ctx context.Context, daemon string) (SSHEnvelope, error) {
	var r SSHEnvelope
	err := c.doJSON(ctx, http.MethodGet, "/daemons/"+url.PathEscape(daemon)+"/ssh", nil, true, "", false, &r)
	return r, err
}
func (c *Client) AddSSHKey(ctx context.Context, daemon, key, idem string) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	var r OperationEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemon)+"/ssh/keys", map[string]string{"public_key": key}, true, idem, true, &r)
	return r, err
}
func (c *Client) RemoveSSHKey(ctx context.Context, daemon, key, idem string) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	var r OperationEnvelope
	err := c.doJSON(ctx, http.MethodDelete, "/daemons/"+url.PathEscape(daemon)+"/ssh/keys/"+url.PathEscape(key), nil, true, idem, true, &r)
	return r, err
}
func (c *Client) DisableSSH(ctx context.Context, daemon, idem string) (OperationEnvelope, error) {
	if err := c.Preflight(ctx); err != nil {
		return OperationEnvelope{}, err
	}
	var r OperationEnvelope
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemon)+"/ssh/disable", map[string]any{}, true, idem, true, &r)
	return r, err
}
func (c *Client) SSHTicket(ctx context.Context, daemon string) (SSHTicket, error) {
	var r SSHTicket
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemon)+"/ssh/ticket", map[string]any{}, true, "", true, &r)
	if err == nil && r.Data.Ticket == "" {
		return SSHTicket{}, invalidResponse("data.ticket")
	}
	return r, err
}
func (c *Client) GatewayURL() string {
	u := *c.baseURL
	u.Scheme = map[bool]string{true: "wss", false: "ws"}[u.Scheme == "https"]
	u.Path = "/ssh"
	u.RawQuery = ""
	return u.String()
}
