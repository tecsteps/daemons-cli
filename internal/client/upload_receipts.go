package client

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"regexp"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

type UploadReceipt struct {
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
	Bytes  int64  `json:"bytes,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

var uploadHash = regexp.MustCompile(`^[a-f0-9]{64}$`)

// GetUploadReceipt obtains fresh read authority, never retries or recovers a write.
func (c *Client) GetUploadReceipt(ctx context.Context, daemonID, operationID string) (UploadReceipt, error) {
	if !payloadUUID.MatchString(daemonID) || !payloadUUID.MatchString(operationID) {
		return UploadReceipt{}, errs.New("usage_error", "Daemon and operation UUIDs are required.", 2)
	}
	output := boundedContentJSON{maximum: 32768}
	if err := c.AccessContent(ctx, daemonID, operationID, "files.read", strings.NewReader(`{"operation":"upload_receipt"}`), &output); err != nil {
		return UploadReceipt{}, err
	}
	return decodeUploadReceipt(output.Bytes())
}

func decodeUploadReceipt(raw []byte) (UploadReceipt, error) {
	return decodeUploadReceiptPath(raw, false)
}

func decodeUploadReceiptPath(raw []byte, absolute bool) (UploadReceipt, error) {
	bad := func() (UploadReceipt, error) { return UploadReceipt{}, invalidResponse("upload receipt") }
	decoder := json.NewDecoder(bytes.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return bad()
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] || (name != "status" && name != "path" && name != "bytes" && name != "sha256") {
			return bad()
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return bad()
		}
	}
	if closing, err := decoder.Token(); err != nil || closing != json.Delim('}') {
		return bad()
	}
	if _, err := decoder.Token(); err != io.EOF {
		return bad()
	}
	var receipt UploadReceipt
	if json.Unmarshal(raw, &receipt) != nil || !seen["status"] {
		return bad()
	}
	switch receipt.Status {
	case "not_found", "outcome_unknown":
		if len(seen) != 1 {
			return bad()
		}
	case "applied":
		if len(seen) != 4 || receipt.Bytes < 0 || receipt.Bytes > 1<<30 || !uploadHash.MatchString(receipt.SHA256) ||
			len(receipt.Path) == 0 || len(receipt.Path) > 16384 || strings.ContainsRune(receipt.Path, '\x00') {
			return bad()
		}
		workspacePath := receipt.Path
		if absolute {
			if !strings.HasPrefix(workspacePath, "/") {
				return bad()
			}
			workspacePath = strings.TrimPrefix(workspacePath, "/")
		}
		for _, part := range strings.Split(workspacePath, "/") {
			if part == "" || part == "." || part == ".." {
				return bad()
			}
		}
	default:
		return bad()
	}
	return receipt, nil
}
