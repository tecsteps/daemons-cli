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
	"github.com/tecsteps/daemons-cli/internal/client"
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
	if e = api.ValidateGatewayURL(gateway); e != nil {
		return runResultFor(e)
	}
	prove, e := lockResponder(args[0], "ssh.connect", args[0], opt, d)
	if e != nil {
		return runResultFor(e)
	}
	if e = relaySSH(ctx, gateway, ticket.Data.Ticket, d, prove, api.GatewayHTTPClient()); e != nil {
		var cli *errs.CLIError
		if errors.As(e, &cli) {
			return runResultFor(e)
		}
		code := 1
		if errors.Is(e, errAdmission) {
			code = sshAdmissionRefusedExit
		}
		return runResult{code: code, err: e}
	}
	return runResult{}
}

var errAdmission = errors.New("SSH gateway refused admission")

func admitSSH(ctx context.Context, ws *websocket.Conn, prove func(string) (string, error)) (bool, error) {
	sawChallenge := false
	for {
		typ, data, err := ws.Read(ctx)
		if err != nil {
			if websocket.CloseStatus(err) == 4403 {
				if sawChallenge && prove == nil {
					return false, client.LockDeviceRequired()
				}
				return false, errAdmission
			}
			return false, fmt.Errorf("read SSH admission: %w", err)
		}
		if typ != websocket.MessageText {
			return false, errors.New("gateway sent bytes before ready")
		}
		if client.IsLockDeviceChallenge(data) {
			sawChallenge = true
			if prove == nil {
				return false, client.LockDeviceRequired()
			}
			reply, err := prove(string(data))
			if err != nil {
				return false, err
			}
			if err := ws.Write(ctx, websocket.MessageText, []byte(reply)); err != nil {
				return false, fmt.Errorf("write SSH device proof: %w", err)
			}
			continue
		}
		var frame struct {
			Type    string `json:"type"`
			Code    string `json:"code"`
			Message string `json:"message"`
		}
		if json.Unmarshal(data, &frame) != nil {
			return false, errors.New("invalid SSH gateway control frame")
		}
		if frame.Type == "error" {
			return false, errAdmission
		}
		if string(data) != sshControlReady || frame.Type != "ready" {
			return false, errors.New("gateway did not send ready control frame")
		}
		return true, nil
	}
}

func relaySSH(ctx context.Context, gateway, ticket string, d Dependencies, prove func(string) (string, error), httpClient *http.Client) error {
	if ticket == "" {
		return errors.New("missing SSH ticket")
	}
	if httpClient == nil {
		httpClient = &http.Client{Transport: &http.Transport{Proxy: http.ProxyFromEnvironment}, CheckRedirect: client.RejectGatewayRedirect}
	}
	ws, resp, e := websocket.Dial(ctx, gateway, &websocket.DialOptions{HTTPClient: httpClient, Subprotocols: []string{"dr." + ticket}, CompressionMode: websocket.CompressionDisabled})
	if e != nil {
		if resp != nil && (resp.StatusCode == 401 || resp.StatusCode == 403) {
			return errAdmission
		}
		if websocket.CloseStatus(e) == 4403 {
			return errAdmission
		}
		return errors.New("unable to connect to SSH gateway")
	}
	defer ws.Close(websocket.StatusNormalClosure, "")
	ws.SetReadLimit(sshMaxBinaryFrameBytes)
	ready, err := admitSSH(ctx, ws, prove)
	if err != nil {
		return err
	}
	if !ready {
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
