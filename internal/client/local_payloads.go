package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const maximumLocalPayload = 8 * 1024 * 1024
const maximumSafeInteger = 9007199254740991

var payloadUUID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-8][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

type LocalPayloadTarget struct {
	OrganizationID       string `json:"organization_id"`
	WorkspaceID          string `json:"workspace_id"`
	RuntimeGeneration    int64  `json:"runtime_generation"`
	AssignmentGeneration int64  `json:"assignment_generation"`
}

func (target LocalPayloadTarget) valid(daemonID string) bool {
	return payloadUUID.MatchString(target.OrganizationID) && payloadUUID.MatchString(target.WorkspaceID) && target.WorkspaceID == daemonID &&
		target.RuntimeGeneration > 0 && target.RuntimeGeneration <= maximumSafeInteger &&
		target.AssignmentGeneration > 0 && target.AssignmentGeneration <= maximumSafeInteger
}

type LocalPayloadReceipt struct {
	LocalPayloadTarget
	PayloadID   string  `json:"payload_id"`
	OperationID string  `json:"operation_id"`
	Revision    int64   `json:"revision"`
	Phase       string  `json:"phase"`
	ErrorCode   *string `json:"error_code"`
}

// PutLocalPayload streams the E4 envelope once. An interrupted upload must be
// resolved with LocalPayloadReceipt, not replayed as a file upload or CP mutation.
func (c *Client) PutLocalPayload(ctx context.Context, daemonID, operationID string, source io.Reader) (LocalPayloadReceipt, error) {
	if source == nil {
		return LocalPayloadReceipt{}, errs.New("invalid_payload", "A local payload stream is required.", 2)
	}
	return c.transferLocalPayload(ctx, daemonID, operationID, "local_payload.put", io.LimitReader(source, maximumLocalPayload+1))
}

// GetLocalPayloadReceipt obtains fresh authority after an ambiguous upload.
func (c *Client) GetLocalPayloadReceipt(ctx context.Context, daemonID, operationID string) (LocalPayloadReceipt, error) {
	return c.transferLocalPayload(ctx, daemonID, operationID, "local_payload.receipt", nil)
}

func (c *Client) transferLocalPayload(ctx context.Context, daemonID, operationID, action string, source io.Reader) (LocalPayloadReceipt, error) {
	var empty LocalPayloadReceipt
	if !payloadUUID.MatchString(daemonID) || !payloadUUID.MatchString(operationID) {
		return empty, errs.New("usage_error", "Daemon and operation UUIDs are required.", 2)
	}
	ticket, err := c.MintAccessTicket(ctx, daemonID, operationID, action)
	if err != nil {
		return empty, err
	}
	u := *c.baseURL
	u.Path, u.RawPath = ticket.Data.GatewayPath, ""
	output := boundedContentJSON{maximum: 4096}
	if err := c.relayContentType(ctx, ticket.Data.Method, u.String(), ticket.Data.Ticket, "application/vnd.daemons.local-payload+json", source, &output); err != nil {
		return empty, err
	}
	return decodeLocalPayloadReceipt(output.Bytes(), ticket.Data.Target, operationID)
}

func decodeLocalPayloadReceipt(raw []byte, target LocalPayloadTarget, operationID string) (LocalPayloadReceipt, error) {
	var receipt LocalPayloadReceipt
	bad := func() (LocalPayloadReceipt, error) {
		return LocalPayloadReceipt{}, invalidResponse("local payload receipt")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return bad()
	}
	fields := map[string]bool{"organization_id": false, "workspace_id": false, "runtime_generation": false, "assignment_generation": false,
		"payload_id": false, "operation_id": false, "revision": false, "phase": false, "error_code": false}
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		seen, known := fields[name]
		if err != nil || !ok || !known || seen {
			return bad()
		}
		fields[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return bad()
		}
		if name != "error_code" && bytes.Equal(value, []byte("null")) {
			return bad()
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return bad()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return bad()
	}
	for _, seen := range fields {
		if !seen {
			return bad()
		}
	}
	if json.Unmarshal(raw, &receipt) != nil || receipt.LocalPayloadTarget != target || receipt.PayloadID != operationID || receipt.OperationID != operationID ||
		receipt.Revision < 0 || receipt.Revision > maximumSafeInteger {
		return bad()
	}
	code := ""
	if receipt.ErrorCode != nil {
		code = *receipt.ErrorCode
	}
	switch receipt.Phase {
	case "staged", "committed", "applied":
		if receipt.ErrorCode != nil || receipt.Revision == 0 {
			return bad()
		}
	case "needs_reconcile":
		if code != "needs_reconcile" {
			return bad()
		}
	case "rejected":
		allowed := map[string]bool{"payload_conflict": true, "revision_conflict": true, "invalid_payload": true, "stale_generation": true, "forbidden": true,
			"disk_full": true, "credential_mount_missing": true, "policy_unavailable": true, "needs_reconcile": true, "payload_required": true, "unsupported_version": true}
		if !allowed[code] {
			return bad()
		}
	default:
		return bad()
	}
	return receipt, nil
}

// LocalPayloadUnavailable keeps an unwired lifecycle caller from substituting
// an ordinary file upload. E7 must explicitly integrate PutLocalPayload and
// GetLocalPayloadReceipt before removing its pre-create guard.
func LocalPayloadUnavailable() error {
	return errs.New("local_payload_unavailable", "This lifecycle command is not yet wired to local payload upload. Content remains on your device; no create or upload was submitted.", 2)
}
