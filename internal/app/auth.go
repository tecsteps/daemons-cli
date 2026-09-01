package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/credentials"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

var defaultScopes = []string{
	"control-plane:discover",
	"servers:read",
	"daemons:read",
	"daemons:write",
	"daemons:destroy",
	"operations:read",
	"files:read",
	"files:write",
	"terminal:connect",
	"tasks:read",
	"tasks:write",
	"tasks:cancel",
	"logs:read",
}

const loginUsage = "Usage: daemons login [--scope SCOPE] [--lifetime 7d] | daemons login --token-stdin"

func login(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, loginUsage)
		return nil
	}
	scopes := []string{}
	lifetime := "7d"
	tokenFromStdin := false
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--token-stdin":
			tokenFromStdin = true
		case "--scope":
			if index+1 >= len(arguments) {
				return errs.New("usage_error", "--scope requires a value.", 2)
			}
			scopes = append(scopes, arguments[index+1])
			index++
		case "--lifetime":
			if index+1 >= len(arguments) {
				return errs.New("usage_error", "--lifetime requires a value.", 2)
			}
			lifetime = arguments[index+1]
			index++
		default:
			return errs.New("usage_error", loginUsage, 2)
		}
	}
	if tokenFromStdin {
		if len(scopes) != 0 || lifetime != "7d" {
			return errs.New("usage_error", "--token-stdin stores an existing token; --scope and --lifetime apply only to the device flow.", 2)
		}
		return loginWithStdinToken(ctx, options, dependencies)
	}
	if len(scopes) == 0 {
		scopes = append(scopes, defaultScopes...)
	}

	api, normalized, err := newClient(options.Host, "", options, dependencies)
	if err != nil {
		return err
	}
	authorization, err := api.CreateDeviceAuthorization(ctx, scopes, lifetime)
	if err != nil {
		return err
	}
	if authorization.Data.DeviceCode == "" || authorization.Data.VerificationURL == "" {
		return errs.New("invalid_device_authorization", "The Control Plane returned an invalid device authorization.", 1)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, authorization.Raw)
	} else {
		fmt.Fprintf(dependencies.Output, "Open %s\nEnter device code: %s\nWaiting for approval...\n", authorization.Data.VerificationURL, authorization.Data.DeviceCode)
	}
	if dependencies.IsInteractive() && dependencies.OpenURL != nil && safeBrowserURL(authorization.Data.VerificationURL) {
		if openErr := dependencies.OpenURL(authorization.Data.VerificationURL); openErr != nil {
			fmt.Fprintf(dependencies.ErrorOutput, "Could not open a browser; open %s manually.\n", authorization.Data.VerificationURL)
		}
	}

	interval := time.Duration(authorization.Data.IntervalSeconds) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	expiresAt, _ := time.Parse(time.RFC3339, authorization.Data.ExpiresAt)
	for expiresAt.IsZero() || dependencies.Now().Before(expiresAt) {
		if err := dependencies.Sleep(ctx, interval); err != nil {
			return errs.New("login_interrupted", "Login was interrupted.", 1)
		}

		status, pollErr := api.PollDeviceAuthorization(ctx, authorization.Data.DeviceCode)
		if pollErr != nil {
			if client.IsAPIError(pollErr, "slow_down") {
				interval += 5 * time.Second
			} else if client.IsAPIError(pollErr, "authorization_rejected") || client.IsAPIError(pollErr, "authorization_expired") {
				return errs.New(errs.Code(pollErr), pollErr.Error(), 3)
			} else {
				return pollErr
			}
		} else if status.Data.Status == "approved" && status.Data.AccessToken != "" {
			authenticated, _, err := newClient(normalized, status.Data.AccessToken, options, dependencies)
			if err != nil {
				return err
			}
			return verifyAndStoreToken(ctx, authenticated, normalized, status.Data.AccessToken, "approved", options, dependencies)
		} else if status.Data.Status != "pending" {
			return errs.New("invalid_device_authorization", "The Control Plane returned an invalid device authorization status.", 1)
		}
	}

	return errs.New("authorization_expired", "The device authorization expired before approval.", 3)
}

// loginWithStdinToken reads one token line from stdin, verifies it against
// /me, and stores it under the normalized host. The token is never accepted
// as an argument, never echoed, and never written anywhere but the store.
func loginWithStdinToken(ctx context.Context, options globalOptions, dependencies Dependencies) error {
	if dependencies.IsInteractive() && !options.Quiet {
		fmt.Fprintln(dependencies.ErrorOutput, "Reading the Control Plane token from stdin (one line, then Ctrl-D)...")
	}
	raw, err := io.ReadAll(io.LimitReader(dependencies.Input, 4097))
	if err != nil {
		return errs.New("token_unreadable", "Could not read the token from stdin.", 2)
	}
	token := strings.TrimSpace(string(raw))
	if token == "" || len(raw) > 4096 || strings.ContainsAny(token, " \t\r\n") {
		return errs.New("invalid_token_input", "stdin must contain exactly one token on a single line.", 2)
	}
	api, normalized, err := newClient(options.Host, token, options, dependencies)
	if err != nil {
		return err
	}
	return verifyAndStoreToken(ctx, api, normalized, token, "stored", options, dependencies)
}

func verifyAndStoreToken(ctx context.Context, api *client.Client, normalized, token, status string, options globalOptions, dependencies Dependencies) error {
	identity, err := api.Me(ctx)
	if err != nil {
		return err
	}
	store, err := credentialStore(options, dependencies.Environment)
	if err != nil {
		return err
	}
	if err := store.Save(credentials.Credential{
		BaseURL:      normalized,
		Token:        token,
		AccountEmail: identity.Data.Account.Email,
		ExpiresAt:    identity.Data.Token.ExpiresAt,
	}); err != nil {
		return errs.New("credential_write_failed", "Could not store credentials in the owner-only credential file.", 1)
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{"data": map[string]any{"status": status, "email": identity.Data.Account.Email, "host": normalized}, "meta": map[string]any{}})
	} else {
		fmt.Fprintf(dependencies.Output, "Logged in as %s at %s.\n", identity.Data.Account.Email, normalized)
	}
	return nil
}

func logout(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons logout")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons logout", 2)
	}
	api, normalized, store, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	idempotencyKey, err := dependencies.NewIdempotencyKey()
	if err != nil {
		return errs.New("idempotency_key_unavailable", "Could not generate an idempotency key for token revocation.", 1)
	}
	if err := api.Logout(ctx, idempotencyKey); err != nil {
		if errs.ExitCode(err) == 8 {
			return errs.New("logout_outcome_unknown", "Token revocation could not be confirmed. Local credentials were preserved.", 8)
		}
		return err
	}
	usedEnvironmentToken := dependencies.Environment["DAEMONS_TOKEN"] != ""
	if !usedEnvironmentToken {
		if err := store.Delete(normalized); err != nil {
			return errs.New("credential_delete_failed", "The token was revoked, but the local credential file could not be removed.", 1)
		}
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{"data": map[string]any{"revoked": true}, "meta": map[string]any{}})
	} else if usedEnvironmentToken {
		fmt.Fprintln(dependencies.Output, "Logged out. The Control Plane token from DAEMONS_TOKEN was revoked.")
	} else {
		fmt.Fprintln(dependencies.Output, "Logged out. The Control Plane token was revoked and removed locally.")
	}
	return nil
}

func whoami(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons whoami")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons whoami", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	identity, err := api.Me(ctx)
	if err != nil {
		return err
	}
	if options.JSON {
		writeJSON(dependencies.Output, identity)
	} else {
		fmt.Fprintf(dependencies.Output, "%s\n", identity.Data.Account.Email)
	}
	return nil
}

func capabilities(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons capabilities")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons capabilities", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.Capabilities(ctx)
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}
	for _, capability := range result.Data {
		status := "disabled"
		if capability.Enabled {
			status = "enabled"
		}
		reason := ""
		if capability.Reason != nil {
			reason = " (" + *capability.Reason + ")"
		}
		fmt.Fprintf(dependencies.Output, "%s\t%s%s\n", capability.Name, status, reason)
	}
	return nil
}

func authenticatedClient(options globalOptions, dependencies Dependencies) (*client.Client, string, credentials.Backend, error) {
	store, err := credentialStore(options, dependencies.Environment)
	if err != nil {
		return nil, "", store, err
	}
	token := dependencies.Environment["DAEMONS_TOKEN"]
	baseURL := options.Host
	if token == "" {
		if baseURL == "" {
			baseURL, err = defaultStoredHost(store)
			if err != nil {
				return nil, "", store, err
			}
		}
		normalized, normalizeErr := client.NormalizeBaseURL(baseURL)
		if normalizeErr != nil {
			return nil, "", store, normalizeErr
		}
		credential, loadErr := store.Load(normalized)
		if loadErr != nil {
			if errors.Is(loadErr, fs.ErrNotExist) {
				return nil, "", store, errs.New("authentication_required", "No Control Plane token is stored for "+normalized+". Run daemons login --host "+normalized+".", 3)
			}
			return nil, "", store, errs.New("credential_read_failed", "Could not read the protected credential file.", 3)
		}
		token = credential.Token
		if expiresAt, parseErr := time.Parse(time.RFC3339, credential.ExpiresAt); parseErr == nil && !dependencies.Now().Before(expiresAt) {
			return nil, "", store, errs.New("authentication_expired", "The Control Plane token for "+normalized+" has expired. Run daemons login.", 3)
		}
	}
	api, normalized, err := newClient(baseURL, token, options, dependencies)
	return api, normalized, store, err
}

// defaultStoredHost picks the host when none was given: the production host
// when it has a credential, otherwise the only stored host. Two or more
// non-production hosts are ambiguous and need an explicit --host.
func defaultStoredHost(store credentials.Backend) (string, error) {
	hosts, err := store.Hosts()
	if err != nil {
		return "", errs.New("credential_read_failed", "Could not read the protected credential file.", 3)
	}
	switch {
	case len(hosts) == 0:
		return client.DefaultBaseURL, nil
	case len(hosts) == 1:
		return hosts[0], nil
	}
	for _, host := range hosts {
		if host == client.DefaultBaseURL {
			return host, nil
		}
	}
	return "", errs.New("credential_host_ambiguous", "Credentials are stored for several hosts ("+strings.Join(hosts, ", ")+"). Pass --host or set DAEMONS_HOST.", 3)
}

func newClient(baseURL, token string, global globalOptions, dependencies Dependencies) (*client.Client, string, error) {
	normalized, err := client.NormalizeBaseURL(baseURL)
	if err != nil {
		return nil, "", err
	}
	clientOptions := []client.Option{
		client.WithVersion(dependencies.Version),
		client.WithRequestID(global.RequestID),
		client.WithWarningSink(func(warning string) {
			fmt.Fprintf(dependencies.ErrorOutput, "Warning: %s\n", warning)
		}),
	}
	if dependencies.HTTPClient != nil {
		clientOptions = append(clientOptions, client.WithHTTPClient(dependencies.HTTPClient))
	}
	api, err := client.New(normalized, token, clientOptions...)
	return api, normalized, err
}

func credentialStore(options globalOptions, environment map[string]string) (credentials.Backend, error) {
	path := options.CredentialsFile
	if path == "" {
		var err error
		path, err = credentials.DefaultPath(environment)
		if err != nil {
			return credentials.Store{}, errs.New("credential_path_unavailable", "Could not determine the credential file path.", 1)
		}
	}
	return credentials.Store{Path: path}, nil
}
