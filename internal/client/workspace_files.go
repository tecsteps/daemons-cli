package client

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	// FilesProtocolLabel is the admitted files working-transport subprotocol.
	FilesProtocolLabel = "dr.workspace-files.v1"
	filesReadLimit     = 262144
	filesChunkBytes    = 32768
)

func (c *Client) filesChannelURL(daemonID string) (string, error) {
	if daemonID == "" || strings.ContainsAny(daemonID, "/?#\\") || strings.Contains(daemonID, "..") {
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
	target.Path = "/v1/workspaces/" + daemonID + "/files/channel"
	target.RawPath = ""
	target.RawQuery = ""
	target.Fragment = ""
	target.User = nil
	return target.String(), nil
}

func (c *Client) accessFilesChannel(ctx context.Context, daemonID, action string, ticket AccessTicket, source io.Reader, destination io.Writer) error {
	var prove func(string) (string, error)
	if c.workingProof != nil {
		callback, err := c.workingProof(action)
		if err != nil {
			return err
		}
		prove = callback
	}
	gateway, err := c.filesChannelURL(daemonID)
	if err != nil {
		return err
	}
	if err := c.ValidateGatewayURL(gateway); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Duration(ticket.Data.ExpiresIn+5)*time.Second)
	defer cancel()

	connection, response, err := websocket.Dial(ctx, gateway, &websocket.DialOptions{
		HTTPClient:      c.GatewayHTTPClient(),
		Subprotocols:    []string{FilesProtocolLabel, "dr." + ticket.Data.Ticket},
		CompressionMode: websocket.CompressionDisabled,
	})
	if err != nil {
		if response != nil {
			response.Body.Close()
		}
		return filesChannelUnavailable()
	}
	defer connection.CloseNow()
	if connection.Subprotocol() != FilesProtocolLabel {
		return errs.New("files_protocol_unsupported",
			"The gateway did not accept the workspace files protocol. Upgrade daemons.", 2)
	}
	connection.SetReadLimit(filesReadLimit)

	requestBody, uploadSource, err := filesRequestBody(action, source)
	if err != nil {
		return err
	}

	sawChallenge := false
	for {
		kind, data, err := connection.Read(ctx)
		if err != nil {
			return filesChannelReadError(err, sawChallenge, prove)
		}
		if kind != websocket.MessageText {
			return filesChannelUnavailable()
		}
		frameType, err := filesFrameType(data)
		if err != nil {
			return err
		}
		switch frameType {
		case "lock_device_challenge":
			if sawChallenge || !IsLockDeviceChallenge(data) {
				return filesChannelUnavailable()
			}
			sawChallenge = true
			if prove == nil {
				_ = connection.Close(websocket.StatusNormalClosure, "lock_required")
				return LockDeviceRequired()
			}
			reply, err := prove(string(data))
			if err != nil {
				_ = connection.Close(websocket.StatusNormalClosure, "lock_required")
				return err
			}
			if err := connection.Write(ctx, websocket.MessageText, []byte(reply)); err != nil {
				return filesChannelUnavailable()
			}
		case "file_ready":
			payload, err := json.Marshal(map[string]any{"type": "file_request", "body": requestBody})
			if err != nil {
				return filesChannelUnavailable()
			}
			if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
				return filesChannelUnavailable()
			}
			if action == "files.download" {
				return consumeFileDownload(ctx, connection, destination)
			}
			if action == "files.upload" {
				return produceFileUpload(ctx, connection, uploadSource, destination)
			}
			return consumeFileResult(ctx, connection, destination)
		case "file_error":
			return filesChannelUnavailable()
		default:
			return filesChannelUnavailable()
		}
	}
}

func filesRequestBody(action string, source io.Reader) (map[string]any, io.Reader, error) {
	if action == "files.upload" {
		return readUploadPrelude(source)
	}
	raw, err := io.ReadAll(io.LimitReader(source, 131073))
	if err != nil || len(raw) > 131072 {
		return nil, nil, errs.New("relay_limit", "The guest selector is too large.", 2)
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, nil, filesChannelUnavailable()
	}
	return body, nil, nil
}

func readUploadPrelude(source io.Reader) (map[string]any, io.Reader, error) {
	var header [4]byte
	if _, err := io.ReadFull(source, header[:]); err != nil {
		return nil, nil, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	length := binary.BigEndian.Uint32(header[:])
	if length == 0 || length > 16384 {
		return nil, nil, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	raw := make([]byte, length)
	if _, err := io.ReadFull(source, raw); err != nil {
		return nil, nil, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	var body map[string]any
	if json.Unmarshal(raw, &body) != nil || body == nil {
		return nil, nil, errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	return body, source, nil
}

func consumeFileDownload(ctx context.Context, connection *websocket.Conn, destination io.Writer) error {
	sequence := 0
	for {
		kind, data, err := connection.Read(ctx)
		if err != nil {
			return filesChannelReadError(err, true, func(string) (string, error) { return "", nil })
		}
		if kind != websocket.MessageText {
			return filesChannelUnavailable()
		}
		frameType, err := filesFrameType(data)
		if err != nil {
			return err
		}
		switch frameType {
		case "file_chunk":
			var frame struct {
				Type     string `json:"type"`
				Sequence int    `json:"sequence"`
				Chunk    string `json:"chunk"`
			}
			if json.Unmarshal(data, &frame) != nil || frame.Sequence != sequence || frame.Chunk == "" {
				return filesChannelUnavailable()
			}
			chunk, err := base64.StdEncoding.DecodeString(frame.Chunk)
			if err != nil || len(chunk) == 0 || len(chunk) > filesChunkBytes ||
				base64.StdEncoding.EncodeToString(chunk) != frame.Chunk {
				return filesChannelUnavailable()
			}
			if _, err := destination.Write(chunk); err != nil {
				return errs.New("relay_partial", "The content transfer is incomplete; do not use the partial result.", 8)
			}
			ack, err := json.Marshal(map[string]any{"type": "file_chunk_ack", "sequence": sequence})
			if err != nil {
				return filesChannelUnavailable()
			}
			if err := connection.Write(ctx, websocket.MessageText, ack); err != nil {
				return filesChannelUnavailable()
			}
			sequence++
		case "file_result":
			return nil
		case "file_error":
			return filesChannelUnavailable()
		default:
			return filesChannelUnavailable()
		}
	}
}

func produceFileUpload(ctx context.Context, connection *websocket.Conn, source io.Reader, destination io.Writer) error {
	sequence := 0
	total := 0
	buf := make([]byte, filesChunkBytes)
	for {
		kind, data, err := connection.Read(ctx)
		if err != nil {
			return filesChannelReadError(err, true, func(string) (string, error) { return "", nil })
		}
		if kind != websocket.MessageText {
			return filesChannelUnavailable()
		}
		var pull struct {
			Type     string `json:"type"`
			Sequence int    `json:"sequence"`
		}
		if json.Unmarshal(data, &pull) != nil || pull.Type != "file_upload_pull" || pull.Sequence != sequence {
			return filesChannelUnavailable()
		}
		n, readErr := source.Read(buf)
		if n > 0 {
			encoded := base64.StdEncoding.EncodeToString(buf[:n])
			payload, err := json.Marshal(map[string]any{
				"type": "file_upload_chunk", "sequence": sequence, "chunk": encoded,
			})
			if err != nil {
				return filesChannelUnavailable()
			}
			if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
				return filesChannelUnavailable()
			}
			total += n
			sequence++
			if readErr != nil && !errors.Is(readErr, io.EOF) {
				return filesChannelUnavailable()
			}
			continue
		}
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return filesChannelUnavailable()
		}
		payload, err := json.Marshal(map[string]any{
			"type": "file_upload_complete", "sequence": sequence, "bytes": total,
		})
		if err != nil {
			return filesChannelUnavailable()
		}
		if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
			return filesChannelUnavailable()
		}
		return consumeFileResult(ctx, connection, destination)
	}
}

func consumeFileResult(ctx context.Context, connection *websocket.Conn, destination io.Writer) error {
	kind, data, err := connection.Read(ctx)
	if err != nil {
		return filesChannelReadError(err, true, func(string) (string, error) { return "", nil })
	}
	if kind != websocket.MessageText {
		return filesChannelUnavailable()
	}
	frameType, err := filesFrameType(data)
	if err != nil {
		return err
	}
	if frameType == "file_error" {
		return filesChannelUnavailable()
	}
	if frameType != "file_result" {
		return filesChannelUnavailable()
	}
	var frame struct {
		Type string          `json:"type"`
		Data json.RawMessage `json:"data"`
	}
	if json.Unmarshal(data, &frame) != nil || len(frame.Data) == 0 {
		return filesChannelUnavailable()
	}
	if _, err := destination.Write(frame.Data); err != nil {
		return errs.New("relay_partial", "The content transfer is incomplete; do not use the partial result.", 8)
	}
	return nil
}

func filesFrameType(data []byte) (string, error) {
	if len(data) == 0 || len(data) > filesReadLimit {
		return "", filesChannelUnavailable()
	}
	var envelope struct {
		Type string `json:"type"`
	}
	if json.Unmarshal(data, &envelope) != nil || envelope.Type == "" {
		return "", filesChannelUnavailable()
	}
	return envelope.Type, nil
}

func filesChannelUnavailable() error {
	return errs.New("relay_refused", "The gateway refused the content transfer.", 5)
}

func filesChannelReadError(err error, sawChallenge bool, prove func(string) (string, error)) error {
	if websocket.CloseStatus(err) == 4403 {
		if sawChallenge && prove == nil {
			return LockDeviceRequired()
		}
		return filesChannelUnavailable()
	}
	return filesChannelUnavailable()
}
