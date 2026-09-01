package terminal

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const prefixByte byte = 0x1d

type Size struct {
	Cols int
	Rows int
}

type Streams struct {
	Input   io.Reader
	Output  io.Writer
	Resize  <-chan Size
	Signals <-chan os.Signal
}

type Outcome struct {
	ExitCode int
	Detached bool
	Replaced bool
}

func Connect(
	ctx context.Context,
	api *client.Client,
	daemonID string,
	session string,
	size Size,
	streams Streams,
) (Outcome, error) {
	type setupResult struct {
		connection *websocket.Conn
		outcome    Outcome
		err        error
	}
	setupContext, cancelSetup := context.WithCancel(ctx)
	defer cancelSetup()
	setup := make(chan setupResult, 1)
	go func() {
		connection, outcome, err := connectSocket(setupContext, api, daemonID, session, size)
		setup <- setupResult{connection: connection, outcome: outcome, err: err}
	}()

	var connection *websocket.Conn
	select {
	case signal := <-streams.Signals:
		cancelSetup()
		result := <-setup
		if result.connection != nil {
			result.connection.CloseNow()
		}
		return Outcome{ExitCode: exitCodeForSignal(signal)}, nil
	case result := <-setup:
		if result.err != nil {
			return result.outcome, result.err
		}
		connection = result.connection
	}
	defer connection.Close(websocket.StatusNormalClosure, "client_exit")

	return Run(ctx, connection, streams), nil
}

func connectSocket(ctx context.Context, api *client.Client, daemonID, session string, size Size) (*websocket.Conn, Outcome, error) {
	ticket, err := api.MintTicket(ctx, daemonID, session, size.Cols, size.Rows)
	if err != nil {
		return nil, Outcome{ExitCode: errs.ExitCode(err)}, err
	}
	if ticket.Data.Protocol != 1 || ticket.Data.Ticket == "" {
		err := errs.New("terminal_protocol_mismatch", "The gateway terminal protocol is not compatible with this CLI.", 2)
		return nil, Outcome{ExitCode: 2}, err
	}
	if err := validateGatewayURL(ticket.Data.GatewayURL); err != nil {
		return nil, Outcome{ExitCode: 10}, err
	}

	connection, response, err := websocket.Dial(ctx, ticket.Data.GatewayURL, &websocket.DialOptions{
		Subprotocols: []string{"dr." + ticket.Data.Ticket},
	})
	if err != nil {
		exitCode := 1
		if response != nil {
			response.Body.Close()
			switch response.StatusCode {
			case http.StatusUnauthorized:
				exitCode = 3
			case http.StatusForbidden:
				exitCode = 5
			}
		}
		return nil, Outcome{ExitCode: exitCode}, errs.New("gateway_connection_failed", "Unable to connect to the terminal gateway.", exitCode)
	}

	return connection, Outcome{}, nil
}

func Run(ctx context.Context, connection *websocket.Conn, streams Streams) Outcome {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type socketMessage struct {
		messageType websocket.MessageType
		payload     []byte
		err         error
	}
	type inputMessage struct {
		payload []byte
		err     error
	}

	socketMessages := make(chan socketMessage, 1)
	inputMessages := make(chan inputMessage, 1)

	go func() {
		for {
			messageType, payload, err := connection.Read(ctx)
			socketMessages <- socketMessage{messageType: messageType, payload: payload, err: err}
			if err != nil {
				return
			}
		}
	}()

	go func() {
		buffer := make([]byte, 32*1024)
		for {
			count, err := streams.Input.Read(buffer)
			payload := append([]byte(nil), buffer[:count]...)
			inputMessages <- inputMessage{payload: payload, err: err}
			if err != nil {
				return
			}
		}
	}()

	prefixPending := false
	for {
		select {
		case message := <-socketMessages:
			if message.err != nil {
				return outcomeForSocketError(message.err)
			}
			if message.messageType == websocket.MessageBinary {
				if _, err := streams.Output.Write(message.payload); err != nil {
					return Outcome{ExitCode: 9}
				}
			}

		case input := <-inputMessages:
			if len(input.payload) > 0 {
				payload, detach, pending := localPrefix(input.payload, prefixPending)
				prefixPending = pending
				if len(payload) > 0 {
					if err := connection.Write(ctx, websocket.MessageBinary, payload); err != nil {
						return outcomeForSocketError(err)
					}
				}
				if detach {
					connection.Close(websocket.StatusNormalClosure, "detached")
					return Outcome{ExitCode: 0, Detached: true}
				}
			}
			if input.err != nil && !errors.Is(input.err, io.EOF) {
				return Outcome{ExitCode: 1}
			}

		case size := <-streams.Resize:
			if size.Cols < 2 || size.Cols > 1000 || size.Rows < 1 || size.Rows > 1000 {
				continue
			}
			payload, _ := json.Marshal(map[string]any{"type": "resize", "cols": size.Cols, "rows": size.Rows})
			if err := connection.Write(ctx, websocket.MessageText, payload); err != nil {
				return outcomeForSocketError(err)
			}

		case signal := <-streams.Signals:
			connection.Close(websocket.StatusNormalClosure, "signal")
			return Outcome{ExitCode: exitCodeForSignal(signal)}

		case <-ctx.Done():
			return Outcome{ExitCode: 1}
		}
	}
}

func localPrefix(input []byte, pending bool) ([]byte, bool, bool) {
	output := make([]byte, 0, len(input)+1)
	for _, current := range input {
		if pending {
			switch current {
			case 'd':
				return output, true, false
			case prefixByte:
				output = append(output, prefixByte)
			default:
				output = append(output, prefixByte, current)
			}
			pending = false
			continue
		}
		if current == prefixByte {
			pending = true
			continue
		}
		output = append(output, current)
	}

	return output, false, pending
}

func outcomeForSocketError(err error) Outcome {
	status := websocket.CloseStatus(err)
	switch status {
	case websocket.StatusNormalClosure:
		return Outcome{ExitCode: 0}
	case websocket.StatusCode(4401):
		return Outcome{ExitCode: 3}
	case websocket.StatusCode(4403):
		return Outcome{ExitCode: 5}
	case websocket.StatusCode(4409):
		return Outcome{ExitCode: 11, Replaced: true}
	default:
		return Outcome{ExitCode: 1}
	}
}

func validateGatewayURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "ws" && parsed.Scheme != "wss") || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return errs.New("unsafe_gateway_url", "The Control Plane returned an unsafe terminal gateway URL.", 10)
	}
	if parsed.Scheme == "ws" && !isLoopback(parsed.Hostname()) {
		return errs.New("unsafe_gateway_url", "An unencrypted terminal gateway is allowed only on a loopback development host.", 10)
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func UsageNotice(daemonName, session string) string {
	return fmt.Sprintf(
		"Remote session %s/%s. Workspace files and commands stay on the daemon.\nOnly files you explicitly upload are sent from this device.\nDetach: Ctrl-] d\n",
		daemonName,
		session,
	)
}
