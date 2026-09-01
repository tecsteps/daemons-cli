package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const maximumJSONResponse = 2 << 20

type discoveryEnvelope struct {
	Data struct {
		Version string `json:"version"`
	} `json:"data"`
}

func (c *Client) Preflight(ctx context.Context) error {
	c.preflightMu.Lock()
	defer c.preflightMu.Unlock()
	if c.preflighted {
		return nil
	}

	var discovery discoveryEnvelope
	if err := c.doJSON(ctx, http.MethodGet, "/", nil, true, "", true, &discovery); err != nil {
		return err
	}
	if err := requireCompatibleVersion(discovery.Data.Version); err != nil {
		return err
	}
	c.preflighted = true

	return nil
}

func (c *Client) doJSON(
	ctx context.Context,
	method string,
	requestPath string,
	body any,
	authenticated bool,
	idempotencyKey string,
	requireVersion bool,
	result any,
) error {
	return c.doJSONWithHeaders(ctx, method, requestPath, body, authenticated, idempotencyKey, requireVersion, nil, result)
}

// doJSONWithHeaders is doJSON with extra request headers such as If-Match.
// It never creates an idempotency key; the caller owns that decision.
func (c *Client) doJSONWithHeaders(
	ctx context.Context,
	method string,
	requestPath string,
	body any,
	authenticated bool,
	idempotencyKey string,
	requireVersion bool,
	headers http.Header,
	result any,
) error {
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}

	request, err := c.newRequest(ctx, method, requestPath, requestBody, authenticated)
	if err != nil {
		return err
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if idempotencyKey != "" {
		request.Header.Set("Idempotency-Key", idempotencyKey)
	}
	for name, values := range headers {
		for _, value := range values {
			request.Header.Add(name, value)
		}
	}

	response, err := c.http.Do(request)
	if err != nil {
		if idempotencyKey != "" {
			return errs.New("outcome_unknown", "The mutation outcome is unknown. Reconcile the resource before retrying with the same idempotency key.", 8)
		}
		return errs.New("network_error", "Unable to reach the daemons.run Control Plane API.", 1)
	}
	defer response.Body.Close()
	c.observeLifecycleHeaders(response)
	if err := c.checkVersion(response, requireVersion); err != nil {
		return err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return decodeAPIError(response)
	}
	if result == nil || response.StatusCode == http.StatusNoContent {
		return nil
	}

	raw, err := io.ReadAll(io.LimitReader(response.Body, maximumJSONResponse+1))
	if err != nil || len(raw) > maximumJSONResponse || !json.Valid(raw) {
		if idempotencyKey != "" {
			return errs.New("outcome_unknown", "The mutation was accepted but its response was invalid. Reconcile the resource before retrying with the same idempotency key.", 8)
		}
		return errs.New("invalid_response", "The Control Plane API returned invalid JSON.", 1)
	}
	if err := json.Unmarshal(raw, result); err != nil {
		if idempotencyKey != "" {
			return errs.New("outcome_unknown", "The mutation was accepted but its response was invalid. Reconcile the resource before retrying with the same idempotency key.", 8)
		}
		return errs.New("invalid_response", "The Control Plane API returned invalid JSON.", 1)
	}
	if envelope, ok := result.(rawEnvelope); ok {
		envelope.setRaw(append(json.RawMessage(nil), raw...))
	}
	if receiver, ok := result.(headerReceiver); ok {
		receiver.setResponseHeaders(response.Header)
	}

	return nil
}

func (c *Client) newRequest(ctx context.Context, method, requestPath string, body io.Reader, authenticated bool) (*http.Request, error) {
	if authenticated && c.token == "" {
		return nil, errs.New("authentication_required", "No Control Plane token is available. Run daemons login.", 3)
	}

	endpoint := *c.baseURL
	requestPath, query, _ := strings.Cut(requestPath, "?")
	endpoint.Path = path.Join(c.baseURL.Path, requestPath)
	endpoint.RawQuery = query
	request, err := http.NewRequestWithContext(ctx, method, endpoint.String(), body)
	if err != nil {
		return nil, fmt.Errorf("create request: %w", err)
	}
	request.Header.Set("Accept", "application/json, application/problem+json")
	request.Header.Set("User-Agent", "daemons/"+c.version)
	request.Header.Set("X-Daemons-CLI-Version", c.version)
	if c.requestID != "" {
		request.Header.Set("X-Request-Id", c.requestID)
	}
	if authenticated {
		request.Header.Set("Authorization", "Bearer "+c.token)
	}

	return request, nil
}

func (c *Client) checkVersion(response *http.Response, required bool) error {
	reported := response.Header.Get("X-Daemons-Api-Version")
	if reported == "" && !required {
		return nil
	}
	return requireCompatibleVersion(reported)
}

func requireCompatibleVersion(value string) error {
	major, ok := apiMajor(value)
	if !ok || major != APIVersion {
		reported := value
		if reported == "" {
			reported = "missing"
		}
		return errs.New("api_version_mismatch", fmt.Sprintf("This CLI supports Control Plane API v%d, but the server reported %s.", APIVersion, reported), 2)
	}
	return nil
}

func apiMajor(value string) (int, bool) {
	value = strings.TrimSpace(strings.TrimPrefix(strings.ToLower(value), "v"))
	if value == "" {
		return 0, false
	}
	if index := strings.IndexAny(value, ".-"); index >= 0 {
		value = value[:index]
	}
	major, err := strconv.Atoi(value)
	return major, err == nil
}

func (c *Client) observeLifecycleHeaders(response *http.Response) {
	deprecation := response.Header.Get("Deprecation")
	sunset := response.Header.Get("Sunset")
	replacement := replacementLink(response.Header.Values("Link"))
	if deprecation == "" && sunset == "" && replacement == "" {
		return
	}

	parts := make([]string, 0, 3)
	if deprecation != "" {
		parts = append(parts, "deprecation="+deprecation)
	}
	if sunset != "" {
		parts = append(parts, "sunset="+sunset)
	}
	if replacement != "" {
		parts = append(parts, "replacement="+replacement)
	}
	warning := "Control Plane API lifecycle warning: " + strings.Join(parts, "; ")

	c.warningMu.Lock()
	if _, exists := c.warnings[warning]; exists {
		c.warningMu.Unlock()
		return
	}
	c.warnings[warning] = struct{}{}
	c.warningMu.Unlock()
	if c.warningSink != nil {
		c.warningSink(warning)
	}
}

func replacementLink(values []string) string {
	for _, value := range values {
		for _, link := range strings.Split(value, ",") {
			if !strings.Contains(strings.ToLower(link), "rel=\"successor-version\"") &&
				!strings.Contains(strings.ToLower(link), "rel=successor-version") {
				continue
			}
			start := strings.Index(link, "<")
			end := strings.Index(link, ">")
			if start >= 0 && end > start {
				return strings.TrimSpace(link[start+1 : end])
			}
		}
	}
	return ""
}

func decodeAPIError(response *http.Response) error {
	raw, _ := io.ReadAll(io.LimitReader(response.Body, maximumJSONResponse+1))
	apiError := &errs.APIError{
		Status:     response.StatusCode,
		RetryAfter: response.Header.Get("Retry-After"),
	}
	if len(raw) <= maximumJSONResponse && json.Valid(raw) {
		apiError.Raw = append(json.RawMessage(nil), raw...)
		_ = json.Unmarshal(raw, apiError)
	}
	apiError.Status = response.StatusCode
	if apiError.RequestID == "" {
		apiError.RequestID = response.Header.Get("X-Request-Id")
	}
	return apiError
}

func (c *Client) upload(ctx context.Context, daemonID, filename string, file *os.File) (UploadResponse, error) {
	reader, writer := io.Pipe()
	multipartWriter := multipart.NewWriter(writer)

	go func() {
		part, err := multipartWriter.CreateFormFile("file", filename)
		if err == nil {
			_, err = io.Copy(part, file)
		}
		if closeErr := multipartWriter.Close(); err == nil {
			err = closeErr
		}
		writer.CloseWithError(err)
	}()

	request, err := c.newRequest(ctx, http.MethodPost, "/daemons/"+url.PathEscape(daemonID)+"/files", reader, true)
	if err != nil {
		reader.Close()
		return UploadResponse{}, err
	}
	request.Header.Set("Content-Type", multipartWriter.FormDataContentType())

	response, err := c.http.Do(request)
	if err != nil {
		return UploadResponse{}, errs.New(
			"upload_outcome_unknown",
			"The upload outcome is unknown. Check the daemon uploads directory before retrying.",
			8,
		)
	}
	defer response.Body.Close()
	c.observeLifecycleHeaders(response)
	if err := c.checkVersion(response, true); err != nil {
		return UploadResponse{}, err
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		err := decodeAPIError(response)
		var apiError *errs.APIError
		if errors.As(err, &apiError) {
			switch response.StatusCode {
			case http.StatusInsufficientStorage:
				apiError.Code = "daemon_storage_full"
			case http.StatusRequestEntityTooLarge, http.StatusUnprocessableEntity:
				apiError.Code = "file_too_large"
				if messages := apiError.Errors["file"]; len(messages) > 0 {
					apiError.Detail = messages[0]
				}
			default:
				if apiError.Code == "" {
					apiError.Code = "upload_failed"
				}
			}
		}
		return UploadResponse{}, err
	}

	var result UploadResponse
	if err := json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&result); err != nil {
		return UploadResponse{}, errs.New("unsafe_server_path", "The Control Plane returned an invalid upload response.", 10)
	}
	return result, nil
}

func legacyIdempotencyKey() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return fmt.Sprintf("cli-%d", time.Now().UnixNano())
	}
	return "cli-" + hex.EncodeToString(value)
}
