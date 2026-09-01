package terminal

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/tecsteps/daemons-cli/internal/client"
)

func TestAttachNegotiatesTicketForwardsBytesResizesAndDetaches(t *testing.T) {
	ticketRequested := make(chan map[string]any, 1)
	clientBytes := make(chan []byte, 1)
	resize := make(chan map[string]any, 1)
	remoteBytes := make(chan []byte, 1)
	inputReader, inputWriter := io.Pipe()
	defer inputReader.Close()
	resizeInput := make(chan Size, 1)

	var server *httptest.Server
	server = httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		switch request.URL.Path {
		case "/api/v1":
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			io.WriteString(writer, `{"data":{"version":"v1"},"meta":{}}`)
		case "/api/v1/daemons/daemon-uuid/terminal-tickets":
			if request.Header.Get("Authorization") != "Bearer dr_cp_test" {
				t.Errorf("authorization = %q", request.Header.Get("Authorization"))
			}
			var body map[string]any
			if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
				t.Errorf("decode ticket request: %v", err)
			}
			ticketRequested <- body
			writer.Header().Set("Content-Type", "application/json")
			writer.Header().Set("X-Daemons-Api-Version", "v1")
			json.NewEncoder(writer).Encode(map[string]any{
				"data": map[string]any{
					"gateway_url":       "ws" + strings.TrimPrefix(server.URL, "http") + "/term",
					"ticket":            "fake.ticket",
					"expires_in":        "30.00",
					"terminal_protocol": "1",
					"features":          []string{"takeover_v1"},
				},
				"meta": []any{},
			})

		case "/term":
			connection, err := websocket.Accept(writer, request, &websocket.AcceptOptions{
				Subprotocols:       []string{"dr.fake.ticket"},
				InsecureSkipVerify: true,
			})
			if err != nil {
				t.Errorf("Accept() error = %v", err)
				return
			}
			defer connection.CloseNow()
			if connection.Subprotocol() != "dr.fake.ticket" {
				t.Errorf("subprotocol = %q", connection.Subprotocol())
			}
			if err := connection.Write(request.Context(), websocket.MessageBinary, []byte("remote output")); err != nil {
				t.Errorf("write remote output: %v", err)
				return
			}
			messageType, payload, err := connection.Read(request.Context())
			if err != nil || messageType != websocket.MessageBinary {
				t.Errorf("read client bytes: type=%v err=%v", messageType, err)
				return
			}
			clientBytes <- payload

			messageType, payload, err = connection.Read(request.Context())
			if err != nil || messageType != websocket.MessageText {
				t.Errorf("read resize: type=%v err=%v", messageType, err)
				return
			}
			var frame map[string]any
			if err := json.Unmarshal(payload, &frame); err != nil {
				t.Errorf("decode resize: %v", err)
				return
			}
			resize <- frame

			_, _, _ = connection.Read(request.Context())
		}
	}))
	defer server.Close()

	api, err := client.New(server.URL, "dr_cp_test", client.WithVersion("test"))
	if err != nil {
		t.Fatal(err)
	}
	outcomes := make(chan Outcome, 1)
	errors := make(chan error, 1)
	go func() {
		outcome, err := Connect(context.Background(), api, "daemon-uuid", "main", Size{Cols: 80, Rows: 24}, Streams{
			Input:  inputReader,
			Output: channelWriter{writes: remoteBytes},
			Resize: resizeInput,
		})
		outcomes <- outcome
		errors <- err
	}()

	select {
	case request := <-ticketRequested:
		if request["session"] != "main" || request["attach_mode"] != "create_or_attach" || request["cols"] != float64(80) || request["rows"] != float64(24) {
			t.Fatalf("ticket request = %#v", request)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("ticket was not requested")
	}

	select {
	case payload := <-remoteBytes:
		if string(payload) != "remote output" {
			t.Fatalf("remote bytes = %q", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("remote bytes were not forwarded")
	}

	if _, err := inputWriter.Write([]byte("local input")); err != nil {
		t.Fatal(err)
	}
	select {
	case payload := <-clientBytes:
		if string(payload) != "local input" {
			t.Fatalf("client bytes = %q", payload)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("client bytes were not forwarded")
	}

	resizeInput <- Size{Cols: 132, Rows: 48}
	select {
	case frame := <-resize:
		if frame["type"] != "resize" || frame["cols"] != float64(132) || frame["rows"] != float64(48) {
			t.Fatalf("resize frame = %#v", frame)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("resize was not propagated")
	}

	if _, err := inputWriter.Write([]byte{prefixByte, 'd'}); err != nil {
		t.Fatal(err)
	}
	select {
	case outcome := <-outcomes:
		if outcome.ExitCode != 0 || !outcome.Detached {
			t.Fatalf("outcome = %#v", outcome)
		}
		if err := <-errors; err != nil {
			t.Fatalf("Connect() error = %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attach did not exit after detach")
	}
}

func TestAttachSignalDuringTicketNegotiationUsesConventionalExitCode(t *testing.T) {
	requestStarted := make(chan struct{}, 1)
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		requestStarted <- struct{}{}
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}
	api, err := client.New("http://127.0.0.1", "dr_cp_test", client.WithHTTPClient(httpClient))
	if err != nil {
		t.Fatal(err)
	}
	signals := make(chan os.Signal, 1)
	outcomes := make(chan Outcome, 1)
	go func() {
		outcome, _ := Connect(context.Background(), api, "daemon-uuid", "main", Size{Cols: 80, Rows: 24}, Streams{
			Input:   strings.NewReader(""),
			Output:  io.Discard,
			Signals: signals,
		})
		outcomes <- outcome
	}()

	select {
	case <-requestStarted:
		signals <- os.Interrupt
	case <-time.After(3 * time.Second):
		t.Fatal("ticket request did not start")
	}
	select {
	case outcome := <-outcomes:
		if outcome.ExitCode != 130 {
			t.Fatalf("signal outcome = %#v", outcome)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("signal did not cancel ticket negotiation")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

type channelWriter struct {
	writes chan<- []byte
}

func (writer channelWriter) Write(payload []byte) (int, error) {
	writer.writes <- append([]byte(nil), payload...)
	return len(payload), nil
}
