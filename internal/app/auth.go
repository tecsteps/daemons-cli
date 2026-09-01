package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
	"operations:read",
	"files:write",
	"terminal:connect",
}

func login(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons login [--scope SCOPE] [--lifetime 7d]")
		return nil
	}
	scopes := []string{}
	lifetime := "7d"
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
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
			return errs.New("usage_error", "Usage: daemons login [--scope SCOPE] [--lifetime 7d]", 2)
		}
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
		writeJSON(dependencies.Output, authorization)
	} else {
		fmt.Fprintf(dependencies.Output, "Open %s\nEnter device code: %s\nWaiting for approval...\n", authorization.Data.VerificationURL, authorization.Data.DeviceCode)
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
			identity, err := authenticated.Me(ctx)
			if err != nil {
				return err
			}
			store, err := credentialStore(options, dependencies.Environment)
			if err != nil {
				return err
			}
			if err := store.Save(credentials.Credential{
				BaseURL:      normalized,
				Token:        status.Data.AccessToken,
				AccountEmail: identity.Data.Account.Email,
				ExpiresAt:    identity.Data.Token.ExpiresAt,
			}); err != nil {
				return errs.New("credential_write_failed", "Could not store credentials in the owner-only credential file.", 1)
			}

			if options.JSON {
				writeJSON(dependencies.Output, map[string]any{"data": map[string]any{"status": "approved", "email": identity.Data.Account.Email}, "meta": map[string]any{}})
			} else {
				fmt.Fprintf(dependencies.Output, "Logged in as %s.\n", identity.Data.Account.Email)
			}
			return nil
		} else if status.Data.Status != "pending" {
			return errs.New("invalid_device_authorization", "The Control Plane returned an invalid device authorization status.", 1)
		}
	}

	return errs.New("authorization_expired", "The device authorization expired before approval.", 3)
}

func logout(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons logout")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons logout", 2)
	}
	api, _, store, err := authenticatedClient(options, dependencies)
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
		if err := store.Delete(); err != nil {
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

func authenticatedClient(options globalOptions, dependencies Dependencies) (*client.Client, string, credentials.Store, error) {
	store, err := credentialStore(options, dependencies.Environment)
	if err != nil {
		return nil, "", store, err
	}
	baseURL := options.Host
	token := dependencies.Environment["DAEMONS_TOKEN"]
	if token == "" {
		credential, loadErr := store.Load()
		if loadErr != nil {
			if errors.Is(loadErr, fs.ErrNotExist) {
				return nil, "", store, errs.New("authentication_required", "No Control Plane token is available. Run daemons login.", 3)
			}
			return nil, "", store, errs.New("credential_read_failed", "Could not read the protected credential file.", 3)
		}
		if baseURL == "" {
			baseURL = credential.BaseURL
		} else {
			normalized, normalizeErr := client.NormalizeBaseURL(baseURL)
			if normalizeErr != nil {
				return nil, "", store, normalizeErr
			}
			if normalized != credential.BaseURL {
				return nil, "", store, errs.New("credential_host_mismatch", "Stored credentials belong to a different Control Plane host.", 3)
			}
		}
		token = credential.Token
		if expiresAt, parseErr := time.Parse(time.RFC3339, credential.ExpiresAt); parseErr == nil && !dependencies.Now().Before(expiresAt) {
			return nil, "", store, errs.New("authentication_expired", "The Control Plane token has expired. Run daemons login.", 3)
		}
	}
	api, normalized, err := newClient(baseURL, token, options, dependencies)
	return api, normalized, store, err
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

func credentialStore(options globalOptions, environment map[string]string) (credentials.Store, error) {
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
