package client

import (
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	APIVersion     = 1
	DefaultBaseURL = "https://daemons.run/api/v1"
)

type Client struct {
	baseURL     *url.URL
	token       string
	http        *http.Client
	version     string
	requestID   string
	warningSink func(string)
	warnings    map[string]struct{}
	warningMu   sync.Mutex
	preflightMu sync.Mutex
	preflighted bool
}

type Option func(*Client)

func WithHTTPClient(httpClient *http.Client) Option {
	return func(client *Client) {
		client.http = httpClient
	}
}

func WithVersion(version string) Option {
	return func(client *Client) {
		client.version = version
	}
}

func WithRequestID(requestID string) Option {
	return func(client *Client) {
		client.requestID = requestID
	}
}

func WithWarningSink(sink func(string)) Option {
	return func(client *Client) {
		client.warningSink = sink
	}
}

func New(baseURL, token string, options ...Option) (*Client, error) {
	normalized, err := NormalizeBaseURL(baseURL)
	if err != nil {
		return nil, err
	}
	parsed, err := url.Parse(normalized)
	if err != nil {
		return nil, err
	}

	client := &Client{
		baseURL:  parsed,
		token:    token,
		http:     &http.Client{Timeout: 30 * time.Second},
		version:  "dev",
		warnings: make(map[string]struct{}),
	}
	for _, option := range options {
		option(client)
	}

	return client, nil
}

func NormalizeBaseURL(value string) (string, error) {
	if value == "" {
		value = DefaultBaseURL
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return "", errs.New("invalid_base_url", "The Control Plane base URL must be an absolute HTTP(S) URL.", 2)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", errs.New("invalid_base_url", "The Control Plane base URL cannot contain credentials, query parameters, or a fragment.", 2)
	}
	if parsed.Scheme == "http" && !isLoopbackHost(parsed.Hostname()) {
		return "", errs.New("invalid_base_url", "Plain HTTP is allowed only for an explicit loopback development host.", 2)
	}

	cleanPath := strings.TrimSuffix(parsed.EscapedPath(), "/")
	if !strings.HasSuffix(cleanPath, "/api/v1") {
		cleanPath += "/api/v1"
	}
	parsed.Path = cleanPath
	parsed.RawPath = ""

	return strings.TrimSuffix(parsed.String(), "/"), nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
