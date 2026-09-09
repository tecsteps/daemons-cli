package client

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

// The admitted lock channel. Admission is ordinary E9: a single-use 30-second
// ticket carrying only public identifiers and the closed action name. No PIN,
// verifier, phrase, device key or proof ever reaches the Control Plane; the
// whole secret exchange is the opaque HPKE frame this file forwards.

// LockTicket is the Control Plane's lock admission response.
type LockTicket struct {
	Data struct {
		Ticket      string  `json:"ticket"`
		Version     int     `json:"ticket_version"`
		ExpiresIn   WireInt `json:"expires_in"`
		Method      string  `json:"method"`
		GatewayPath string  `json:"gateway_path"`
		Protocol    string  `json:"websocket_protocol"`
	} `json:"data"`
	Meta map[string]any `json:"meta"`
}

// LockActionUnlock is the engineer's own unlock. It is one of the lock-channel
// actions this Control Plane admits; every other action in the contract is
// minted through the same route and is refused until the platform carries it.
const LockActionUnlock = "lock.unlock"

// AdmittedLockActions are the lock-channel actions the platform mints today. An
// action outside this set is a version gap and says so, rather than reporting a
// denial the user could act on; an action inside it that is refused is a real
// denial and keeps the Control Plane's own status.
var AdmittedLockActions = []string{
	LockActionUnlock,
	"lock.organization.enroll",
	"lock.organization.recover",
	"lock.organization.rotate",
	"lock.organization.replace",
	"lock.handoff",
	"lock.push_confirmation",
}

func lockActionAdmitted(action string) bool {
	for _, admitted := range AdmittedLockActions {
		if admitted == action {
			return true
		}
	}
	return false
}

// MintLockTicket admits one lock exchange. The action is closed and the
// options carry only the protocol version.
func (c *Client) MintLockTicket(ctx context.Context, daemonID, operationID, action string) (LockTicket, error) {
	var result LockTicket
	if !payloadUUID.MatchString(operationID) || !lockActionPattern.MatchString(action) ||
		!strings.HasPrefix(action, "lock.") {
		return result, invalidResponse("lock ticket request")
	}
	if err := c.Preflight(ctx); err != nil {
		return result, err
	}
	body := map[string]any{"action": action, "operation_uuid": operationID, "protocol_version": 1}
	err := c.doJSON(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/access-tickets", body, true, "", true, &result)
	if err != nil {
		return result, lockAdmissionError(action, err)
	}
	if result.Data.Version != 2 || result.Data.ExpiresIn < 1 || result.Data.ExpiresIn > 30 ||
		result.Data.Method != http.MethodGet || result.Data.Protocol != LockProtocolLabel ||
		result.Data.GatewayPath != "/v1/workspaces/"+daemonID+"/lock" ||
		result.Data.Ticket == "" || len(result.Data.Ticket) > 8192 ||
		strings.ContainsAny(result.Data.Ticket, "\r\n \t") {
		return LockTicket{}, invalidResponse("data.access_ticket")
	}
	return result, nil
}

// lockAdmissionError keeps an unsupported action honest. The contract requires
// failing closed with upgrade guidance rather than degrading to another path.
func lockAdmissionError(action string, err error) error {
	if lockActionAdmitted(action) {
		return err
	}
	var apiError *errs.APIError
	if errors.As(err, &apiError) {
		switch apiError.Status {
		case http.StatusBadRequest, http.StatusNotFound, http.StatusUnprocessableEntity:
			// The action itself is not in this Control Plane's closed map. That
			// is a version gap, not a bad request the user can correct.
			return errs.New("lock_protocol_unsupported",
				"This Control Plane does not admit "+action+" yet. Upgrade the platform before using this command; there is no fallback path.", 2)
		}
	}
	return err
}

// lockGatewayURL binds the exchange to the configured Control Plane authority.
// A ticket never travels in a query string; it is offered as a subprotocol.
func (c *Client) lockGatewayURL(path string) (string, error) {
	if !strings.HasPrefix(path, "/v1/workspaces/") || !strings.HasSuffix(path, "/lock") ||
		strings.ContainsAny(path, "?#\\") {
		return "", unsafeGateway()
	}
	target := *c.baseURL
	switch target.Scheme {
	case "https":
		target.Scheme = "wss"
	case "http":
		target.Scheme = "ws"
	default:
		return "", unsafeGateway()
	}
	target.Path = path
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	target.User = nil
	return target.String(), nil
}

// LockPreparer receives the guest's signed challenge frame and returns the
// sealed request. Verification, pinning and the secret all live inside it: this
// transport never sees a plaintext.
type LockPreparer func(challengeFrame string) (*LockExchange, error)

// ExchangeWorkspaceLock runs the finite three-message lock exchange: the
// guest's signed challenge, one sealed request, one sealed response. It cannot
// select a command, a file or a port, and it is the only exception admitted
// while a workspace is locked.
func (c *Client) ExchangeWorkspaceLock(ctx context.Context, daemonID, operationID, action string, prepare LockPreparer) (map[string]any, error) {
	ticket, err := c.MintLockTicket(ctx, daemonID, operationID, action)
	if err != nil {
		return nil, err
	}
	gateway, err := c.lockGatewayURL(ticket.Data.GatewayPath)
	if err != nil {
		return nil, err
	}
	if err := c.ValidateGatewayURL(gateway); err != nil {
		return nil, err
	}
	// The lease is at most 30 seconds and the guest challenge deadline is the
	// same; nothing here waits longer than the authority it holds.
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ticket.Data.ExpiresIn+5)*time.Second)
	defer cancel()

	connection, response, err := websocket.Dial(ctx, gateway, &websocket.DialOptions{
		HTTPClient:      c.GatewayHTTPClient(),
		Subprotocols:    []string{LockProtocolLabel, "dr." + ticket.Data.Ticket},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		exit := 5
		if response != nil {
			response.Body.Close()
			switch response.StatusCode {
			case http.StatusUnauthorized:
				exit = 3
			case http.StatusConflict:
				exit = 6
			}
		}
		// The dial error can quote the offered subprotocols, ticket included.
		return nil, errs.New("lock_unavailable", "The workspace lock channel refused the connection.", exit)
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != LockProtocolLabel {
		return nil, errs.New("lock_protocol_unsupported",
			"The gateway did not accept the workspace lock protocol. Upgrade daemons.", 2)
	}
	connection.SetReadLimit(LockEnvelopeLimit)

	challengeFrame, err := readLockEnvelope(ctx, connection, "lock_challenge")
	if err != nil {
		return nil, err
	}
	exchange, err := prepare(challengeFrame)
	if err != nil {
		return nil, err
	}
	if exchange == nil || len(exchange.Frame) > LockFrameLimit {
		return nil, LockDenied()
	}
	if err := connection.Write(ctx, websocket.MessageText, []byte(exchange.Frame)); err != nil {
		return nil, LockDenied()
	}
	responseFrame, err := readLockEnvelope(ctx, connection, "lock_response")
	if err != nil {
		return nil, err
	}
	result, err := exchange.Open(responseFrame)
	if err != nil {
		return nil, err
	}
	_ = connection.Close(websocket.StatusNormalClosure, "lock_exchange_complete")
	return result, nil
}

// readLockEnvelope accepts exactly one text {type, frame} envelope of the
// expected type. Binary frames, extra fields and oversized frames are refused.
func readLockEnvelope(ctx context.Context, connection *websocket.Conn, expected string) (string, error) {
	kind, data, err := connection.Read(ctx)
	if err != nil || kind != websocket.MessageText || len(data) > LockEnvelopeLimit {
		return "", LockDenied()
	}
	var envelope map[string]json.RawMessage
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil || decoder.More() {
		return "", LockDenied()
	}
	if len(envelope) != 2 {
		return "", LockDenied()
	}
	var kindValue, frame string
	if err := json.Unmarshal(envelope["type"], &kindValue); err != nil || kindValue != expected {
		return "", LockDenied()
	}
	if err := json.Unmarshal(envelope["frame"], &frame); err != nil || frame == "" || len(frame) > LockFrameLimit {
		return "", LockDenied()
	}
	return frame, nil
}

// ErrLockIdentityOnly ends an exchange after the guest's signed challenge, with
// no request frame sent. Pairing uses it: the user compares the offered
// identity before this client has committed anything to it.
var ErrLockIdentityOnly = errs.New("lock_identity_probe", "The lock exchange ended after the guest identity was read.", 1)

// ReadWorkspaceLockIdentity opens a lock channel only far enough to read and
// structurally validate the guest's signed challenge. No secret, no device key
// and no request frame leave this process.
func (c *Client) ReadWorkspaceLockIdentity(ctx context.Context, daemonID, operationID string, nowMs int64) (LockChallenge, error) {
	var offered LockChallenge
	_, err := c.ExchangeWorkspaceLock(ctx, daemonID, operationID, LockActionUnlock, func(frame string) (*LockExchange, error) {
		challenge, signature, parseErr := ParseLockChallenge(frame)
		if parseErr != nil {
			return nil, parseErr
		}
		// The self-signature proves the challenge is internally consistent. It
		// does not establish trust; the user still compares the pin.
		verified, verifyErr := VerifyLockChallenge(frame, VerifyLockChallengeOptions{
			IdentityPin: challenge.IdentityPin(),
			Scope:       LockScope{WorkspaceUUID: daemonID, Action: challenge.Action},
			NowMs:       nowMs,
		})
		if verifyErr != nil || len(signature) != 64 {
			return nil, LockDenied()
		}
		offered = verified
		return nil, ErrLockIdentityOnly
	})
	if err != nil && !errors.Is(err, ErrLockIdentityOnly) {
		return LockChallenge{}, err
	}
	if offered.Canonical == "" {
		return LockChallenge{}, LockDenied()
	}
	return offered, nil
}
