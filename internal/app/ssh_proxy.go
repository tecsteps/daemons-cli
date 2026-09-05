package app

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const sshAdmissionRefusedExit = 5
const sshControlReady = `{"type":"ready"}`
const sshControlEOF = `{"type":"eof"}`
const sshMaxBinaryFrameBytes = 1024 * 1024

func sshProxy(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons ssh-proxy DAEMON-UUID")
		return runResult{}
	}
	if len(args) != 1 || !uuidPattern.MatchString(args[0]) {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh-proxy DAEMON-UUID", 2))
	}
	api, _, _, e := authenticatedClient(opt, d)
	if e != nil {
		return runResultFor(e)
	}
	ticket, e := api.SSHTicket(ctx, args[0])
	if e != nil {
		return runResultFor(e)
	}
	gateway := ticket.Data.GatewayURL
	if gateway == "" {
		gateway = api.GatewayURL()
	}
	if e = relaySSH(ctx, gateway, ticket.Data.Ticket, d); e != nil {
		code := 1
		if errors.Is(e, errAdmission) {
			code = sshAdmissionRefusedExit
		}
		return runResult{code: code, err: e}
	}
	return runResult{}
}

var errAdmission = errors.New("SSH gateway refused admission")

func relaySSH(ctx context.Context, gateway, ticket string, d Dependencies) error {
	if ticket == "" {
		return errors.New("missing SSH ticket")
	}
	hc := &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}}
	ws, resp, e := websocket.Dial(ctx, gateway, &websocket.DialOptions{HTTPClient: hc, Subprotocols: []string{"dr." + ticket}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return errAdmission
		}
		if websocket.CloseStatus(e) == 4403 {
			return errAdmission
		}
		return fmt.Errorf("connect SSH gateway: %w", e)
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	ws.SetReadLimit(sshMaxBinaryFrameBytes)
	typ, data, e := ws.Read(ctx)
	if e != nil {
		if websocket.CloseStatus(e) == 4403 {
			return errAdmission
		}
		return fmt.Errorf("read SSH admission: %w", e)
	}
	if typ != websocket.MessageText {
		return errors.New("gateway sent bytes before ready")
	}
	var c struct {
		Type    string `json:"type"`
		Code    string `json:"code"`
		Message string `json:"message"`
	}
	if json.Unmarshal(data, &c) != nil {
		return errors.New("invalid SSH gateway control frame")
	}
	if c.Type == "error" {
		fmt.Fprintln(d.ErrorOutput, "SSH gateway:", c.Message)
		return errAdmission
	}
	if string(data) != sshControlReady || c.Type != "ready" {
		return errors.New("gateway did not send ready control frame")
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer func() {
		if closer, ok := d.Input.(io.Closer); ok {
			_ = closer.Close()
		}
	}()
	writeErrors := make(chan error, 1)
	go func() {
		buf := make([]byte, 64*1024)
		for {
			n, rerr := d.Input.Read(buf)
			if n > 0 {
				b := append([]byte(nil), buf[:n]...)
				if e := ws.Write(ctx, websocket.MessageBinary, b); e != nil {
					writeErrors <- e
					return
				}
			}
			if rerr != nil {
				if errors.Is(rerr, io.EOF) {
					_ = ws.Write(ctx, websocket.MessageText, []byte(sshControlEOF))
				}
				return
			}
		}
	}()
	closeOutput := func() {
		if closer, ok := d.Output.(io.Closer); ok {
			_ = closer.Close()
		}
	}
	for {
		typ, b, e := ws.Read(ctx)
		if e != nil {
			cancel()
			closeOutput()
			select {
			case writeErr := <-writeErrors:
				if !errors.Is(writeErr, context.Canceled) {
					return fmt.Errorf("write SSH relay: %w", writeErr)
				}
			default:
			}
			if status := websocket.CloseStatus(e); status != websocket.StatusNormalClosure {
				return fmt.Errorf("SSH gateway closed relay (%d): %w", status, e)
			}
			break
		}
		if typ != websocket.MessageBinary {
			cancel()
			closeOutput()
			return errors.New("unexpected SSH gateway control frame after ready")
		}
		if _, e = d.Output.Write(b); e != nil {
			cancel()
			_ = ws.Close(websocket.StatusGoingAway, "stdout closed")
			closeOutput()
			return fmt.Errorf("write SSH relay output: %w", e)
		}
	}
	return nil
}

var _ = os.Stderr
