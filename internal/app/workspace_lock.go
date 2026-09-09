package app

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/credentials"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/terminal"
)

// The workspace lock commands. Every secret is read from a hidden interactive
// prompt and lives only in memory: there is deliberately no flag, environment
// variable, file or stdin path that carries a PIN, a recovery phrase or an
// organization password, and none of them is ever printed, logged or included
// in JSON output.

const lockUsage = `Usage:
  daemons unlock DAEMON [--trust-on-first-use]
  daemons lock DAEMON
  daemons lock status DAEMON
  daemons lock setup DAEMON
  daemons lock change DAEMON
  daemons lock recover DAEMON
  daemons lock exchanges DAEMON
  daemons lock handoff DAEMON
  daemons lock authorize-replacement DAEMON
  daemons lock pair DAEMON [--forget]`

// lockSecretFlags are refused outright. Naming one is a usage error, not a
// prompt fallback, so a shell history or a process listing never holds a PIN.
var lockSecretFlags = []string{"--pin", "--secret", "--password", "--phrase", "--recovery-phrase", "--pin-stdin", "--secret-stdin"}

func lockCommandHandler(subcommand string) commandHandler {
	return errorHandler(func(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
		return runLockCommand(ctx, subcommand, arguments, options, dependencies)
	})
}

func runLockCommand(ctx context.Context, subcommand string, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, lockUsage)
		return nil
	}
	for _, argument := range arguments {
		for _, refused := range lockSecretFlags {
			if argument == refused || strings.HasPrefix(argument, refused+"=") {
				return errs.New("usage_error",
					"A lock secret is never accepted on the command line. Run the command interactively and type it at the hidden prompt.", 2)
			}
		}
	}
	if len(arguments) < 1 {
		return errs.New("usage_error", lockUsage, 2)
	}
	daemonArgument := arguments[0]
	flags := arguments[1:]

	switch subcommand {
	case "unlock":
		trust := false
		for _, flag := range flags {
			if flag != "--trust-on-first-use" {
				return errs.New("usage_error", lockUsage, 2)
			}
			trust = true
		}
		return unlockWorkspace(ctx, daemonArgument, trust, options, dependencies)
	case "pair":
		forget := false
		for _, flag := range flags {
			if flag != "--forget" {
				return errs.New("usage_error", lockUsage, 2)
			}
			forget = true
		}
		return pairWorkspaceLock(ctx, daemonArgument, forget, options, dependencies)
	}
	if len(flags) != 0 {
		return errs.New("usage_error", lockUsage, 2)
	}
	switch subcommand {
	case "lock":
		return relockWorkspace(ctx, daemonArgument, options, dependencies)
	case "status":
		return workspaceLockStatus(ctx, daemonArgument, options, dependencies)
	case "setup":
		return enrollWorkspaceLock(ctx, daemonArgument, options, dependencies)
	case "change":
		return changeWorkspaceLock(ctx, daemonArgument, options, dependencies)
	case "recover":
		return recoverWorkspaceLock(ctx, daemonArgument, options, dependencies)
	case "exchanges":
		return workspaceLockExchanges(ctx, daemonArgument, options, dependencies)
	case "handoff":
		return approveWorkspaceHandoff(ctx, daemonArgument, options, dependencies)
	case "authorize-replacement":
		return authorizeWorkspaceReplacement(ctx, daemonArgument, options, dependencies)
	}
	return errs.New("usage_error", lockUsage, 2)
}

// ---------------------------------------------------------------------------
// Shared plumbing.
// ---------------------------------------------------------------------------

type lockContext struct {
	api          *client.Client
	baseURL      string
	store        credentials.LockStore
	daemonID     string
	daemonName   string
	dependencies Dependencies
	options      globalOptions
}

func newLockContext(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) (lockContext, error) {
	api, baseURL, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return lockContext{}, err
	}
	store, err := workspaceLockStore(options, dependencies.Environment)
	if err != nil {
		return lockContext{}, err
	}
	// A grant that already expired is removed before anything else reads the
	// store, so a stale device scalar never lingers on disk.
	if err := store.Prune(dependencies.Now().UnixMilli()); err != nil {
		return lockContext{}, lockStoreError(err)
	}
	daemon, err := api.ResolveDaemon(ctx, daemonArgument)
	if err != nil {
		return lockContext{}, err
	}
	return lockContext{api: api, baseURL: baseURL, store: store, daemonID: daemon.ID,
		daemonName: daemon.Name, dependencies: dependencies, options: options}, nil
}

// lockResponder builds the working-transport proof callback for one already
// resolved workspace. It returns nil when this device holds no live grant, so
// an open workspace attaches exactly as before and a protected one refuses with
// the lock code instead of a silent denial. The grant is re-read per challenge:
// a session that outlives the eight-hour deadline stops proving by itself.
func lockResponder(daemonID, action, resourceUUID string, options globalOptions, dependencies Dependencies) (terminal.LockResponder, error) {
	store, err := workspaceLockStore(options, dependencies.Environment)
	if err != nil {
		return nil, err
	}
	_, baseURL, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return nil, err
	}
	context := lockContext{baseURL: baseURL, store: store, daemonID: daemonID, dependencies: dependencies, options: options}
	if _, live, err := context.authority(); err != nil || !live {
		return nil, err
	}
	return func(envelope string) (string, error) {
		current, stillLive, err := context.authority()
		if err != nil {
			return "", err
		}
		if !stillLive {
			return "", errs.New("lock_session_expired", "The device session expired. Unlock again.", 5)
		}
		return current.RespondToLockDeviceChallenge(envelope, action, resourceUUID, context.nowMs())
	}, nil
}

func withWorkingProof(api *client.Client, daemonID string, options globalOptions, dependencies Dependencies) *client.Client {
	api.SetWorkingProof(func(action string) (func(string) (string, error), error) {
		return lockResponder(daemonID, action, daemonID, options, dependencies)
	})
	return api
}

func workspaceLockStore(options globalOptions, environment map[string]string) (credentials.LockStore, error) {
	if configured := environment["DAEMONS_WORKSPACE_LOCK_FILE"]; configured != "" {
		return credentials.LockStore{Path: configured}, nil
	}
	if options.CredentialsFile != "" {
		return credentials.LockStore{Path: filepath.Join(filepath.Dir(options.CredentialsFile), "workspace-lock.json")}, nil
	}
	path, err := credentials.DefaultLockPath(environment)
	if err != nil {
		return credentials.LockStore{}, errs.New("credential_path_unavailable", "Could not determine the workspace lock store path.", 1)
	}
	return credentials.LockStore{Path: path}, nil
}

func lockStoreError(err error) error {
	switch {
	case err == nil:
		return nil
	case errors.Is(err, credentials.ErrLockPinChanged):
		return errs.New("lock_identity_changed",
			"The workspace guest identity changed. Run daemons lock pair to compare and accept the new identity.", 5)
	case errors.Is(err, credentials.ErrLockPinUnknown):
		return errs.New("lock_identity_unpinned",
			"This device has not pinned the workspace guest identity. Run daemons lock pair first.", 5)
	}
	return errs.New("lock_store_unavailable", "The workspace lock store could not be read or written.", 1)
}

func (l lockContext) nowMs() int64 { return l.dependencies.Now().UnixMilli() }

// authority rebuilds this device's live grant from the store. It is the single
// place a stored scalar becomes a signing key, so every caller inherits the
// same expiry and binding checks.
func (l lockContext) authority() (client.LockDeviceAuthority, bool, error) {
	record, err := l.store.Read(l.baseURL, l.daemonID, l.nowMs())
	if err != nil {
		if errors.Is(err, credentials.ErrLockPinUnknown) {
			return client.LockDeviceAuthority{}, false, nil
		}
		return client.LockDeviceAuthority{}, false, lockStoreError(err)
	}
	if record.Grant == nil {
		return client.LockDeviceAuthority{}, false, nil
	}
	device, err := client.LockDeviceKeyFromScalar(record.Grant.DeviceScalar)
	if err != nil {
		return client.LockDeviceAuthority{}, false, err
	}
	authority := client.LockDeviceAuthority{
		Device:               device,
		SessionUUID:          record.Grant.DeviceSessionUUID,
		IdentityPin:          record.IdentityPin,
		OrganizationUUID:     record.OrganizationUUID,
		WorkspaceUUID:        l.daemonID,
		BootUUID:             record.Grant.BootUUID,
		ActorSubjectUUID:     record.Grant.ActorSubjectUUID,
		MembershipUUID:       record.Grant.MembershipUUID,
		AssignmentGeneration: record.AssignmentGeneration,
		LockEpoch:            record.Grant.LockEpoch,
		CredentialRevision:   record.Grant.CredentialRevision,
		ExpiresAtMs:          record.Grant.ExpiresAtMs,
	}
	return authority, authority.Live(l.nowMs()), nil
}

// verifyChallenge is the only place a guest challenge becomes trusted. Nothing
// downstream of it may use an unverified field.
func (l lockContext) verifyChallenge(frame, action string, trustOnFirstUse bool) (client.LockChallenge, error) {
	now := l.nowMs()
	record, err := l.store.Read(l.baseURL, l.daemonID, now)
	switch {
	case err == nil:
		return client.VerifyLockChallenge(frame, client.VerifyLockChallengeOptions{
			IdentityPin: record.IdentityPin,
			Scope: client.LockScope{
				OrganizationUUID:     record.OrganizationUUID,
				WorkspaceUUID:        l.daemonID,
				AssignmentGeneration: record.AssignmentGeneration,
				Action:               action,
			},
			NowMs: now,
		})
	case errors.Is(err, credentials.ErrLockPinUnknown):
		if !trustOnFirstUse {
			return client.LockChallenge{}, errs.New("lock_identity_unpinned",
				"This device has not pinned the workspace guest identity. Run daemons lock pair, or pass --trust-on-first-use to accept the identity this session offers.", 5)
		}
		return l.bootstrapPin(frame, action, now)
	}
	return client.LockChallenge{}, lockStoreError(err)
}

// bootstrapPin accepts an identity for the first time. The signature is still
// checked against the offered key, so a corrupted or truncated challenge is
// refused, but the binding itself is trust on first use and is disclosed as
// such rather than being reported as verified.
func (l lockContext) bootstrapPin(frame, action string, now int64) (client.LockChallenge, error) {
	offered, _, err := client.ParseLockChallenge(frame)
	if err != nil {
		return client.LockChallenge{}, err
	}
	challenge, err := client.VerifyLockChallenge(frame, client.VerifyLockChallengeOptions{
		IdentityPin: offered.IdentityPin(),
		Scope:       client.LockScope{WorkspaceUUID: l.daemonID, Action: action},
		NowMs:       now,
	})
	if err != nil {
		return client.LockChallenge{}, err
	}
	if err := l.store.Pin(credentials.LockScope{
		BaseURL:              l.baseURL,
		OrganizationUUID:     challenge.OrganizationUUID,
		WorkspaceUUID:        l.daemonID,
		AssignmentGeneration: challenge.AssignmentGeneration,
	}, challenge.IdentityPin(), credentials.LockPinTrustedProvisioning); err != nil {
		return client.LockChallenge{}, lockStoreError(err)
	}
	fmt.Fprintf(l.dependencies.ErrorOutput,
		"Trusting the workspace guest identity %s on first use. This is a bootstrap, not a verified pairing: compare it with an already trusted device using daemons lock pair.\n",
		challenge.IdentityPin())
	return challenge, nil
}

// exchange runs one sealed request and its single response.
func (l lockContext) exchange(ctx context.Context, action, operationID string, device client.LockDeviceKey,
	trustOnFirstUse bool, body func(client.LockChallenge) (map[string]any, error),
) (map[string]any, client.LockChallenge, error) {
	var verified client.LockChallenge
	result, err := l.api.ExchangeWorkspaceLock(ctx, l.daemonID, operationID, action, func(frame string) (*client.LockExchange, error) {
		challenge, err := l.verifyChallenge(frame, action, trustOnFirstUse)
		if err != nil {
			return nil, err
		}
		fields, err := body(challenge)
		if err != nil {
			return nil, err
		}
		verified = challenge
		return client.SealLockRequest(challenge, device, fields)
	})
	if err != nil {
		return nil, verified, err
	}
	return result, verified, nil
}

// readSecret takes a factor from a hidden interactive prompt only.
func readLockSecret(dependencies Dependencies, prompt string) (client.LockSecret, error) {
	value, err := readHiddenValue(dependencies, prompt)
	if err != nil {
		return "", err
	}
	secret := client.LockSecret(value)
	if !secret.Valid() {
		return "", errs.New("usage_error", "A PIN is exactly four or six digits.", 2)
	}
	return secret, nil
}

func readHiddenValue(dependencies Dependencies, prompt string) (string, error) {
	if dependencies.ReadSecret == nil || !dependencies.IsInteractive() {
		return "", errs.New("tty_required",
			"A lock secret can only be typed at a hidden interactive prompt. Run this command from a terminal.", 2)
	}
	value, err := dependencies.ReadSecret(prompt)
	if err != nil {
		return "", errs.New("tty_required", "The hidden prompt could not read input.", 2)
	}
	return value, nil
}

// readNewSecret requires the PIN twice. The two entries are compared in memory
// and both are dropped immediately afterwards.
func readNewLockSecret(dependencies Dependencies) (client.LockSecret, error) {
	first, err := readLockSecret(dependencies, "New PIN (4 or 6 digits): ")
	if err != nil {
		return "", err
	}
	second, err := readLockSecret(dependencies, "Repeat the new PIN: ")
	if err != nil {
		return "", err
	}
	if first != second {
		return "", errs.New("usage_error", "The two PIN entries differ.", 2)
	}
	return first, nil
}

// ---------------------------------------------------------------------------
// unlock
// ---------------------------------------------------------------------------

func unlockWorkspace(ctx context.Context, daemonArgument string, trustOnFirstUse bool, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	// The PIN is read before admission so a 30-second lease is never spent
	// waiting for typing.
	secret, err := readLockSecret(dependencies, "Workspace PIN: ")
	if err != nil {
		return err
	}
	device, err := client.NewLockDeviceKey()
	if err != nil {
		return err
	}
	body, err := client.LockUnlockBody(secret)
	if err != nil {
		return err
	}
	secret = ""
	result, challenge, err := lock.exchange(ctx, client.LockActionUnlock, client.NewLockOperationID(), device, trustOnFirstUse,
		func(client.LockChallenge) (map[string]any, error) { return body, nil })
	if err != nil {
		return err
	}
	unlocked, err := client.ReadLockUnlockResult(result, lock.nowMs())
	if err != nil {
		return err
	}
	grant := credentials.LockGrant{
		DeviceSessionUUID:  unlocked.DeviceSessionUUID,
		DeviceScalar:       device.Scalar(),
		ExpiresAtMs:        unlocked.ExpiresAtMs,
		BootUUID:           challenge.BootUUID,
		LockEpoch:          challenge.LockEpoch,
		CredentialRevision: challenge.CredentialRevision,
		ActorSubjectUUID:   challenge.ActorSubjectUUID,
		MembershipUUID:     challenge.MembershipUUID,
	}
	scope := credentials.LockScope{
		BaseURL:              lock.baseURL,
		OrganizationUUID:     challenge.OrganizationUUID,
		WorkspaceUUID:        lock.daemonID,
		AssignmentGeneration: challenge.AssignmentGeneration,
	}
	if err := lock.store.Grant(scope, challenge.IdentityPin(), grant, lock.nowMs()); err != nil {
		return lockStoreError(err)
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{
				"workspace":  lock.daemonID,
				"state":      "unlocked",
				"expires_at": lockTime(unlocked.ExpiresAtMs),
			},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output,
		"Unlocked %s on this device until %s. The grant does not renew: unlock again after it expires.\n",
		lock.daemonName, lockTime(unlocked.ExpiresAtMs))
	return nil
}

func lockTime(milliseconds int64) string {
	return time.UnixMilli(milliseconds).UTC().Format(time.RFC3339)
}

// ---------------------------------------------------------------------------
// lock (relock)
// ---------------------------------------------------------------------------

func relockWorkspace(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	authority, live, err := lock.authority()
	if err != nil {
		return err
	}
	if !live {
		if err := lock.store.Revoke(lock.baseURL, lock.daemonID); err != nil {
			return lockStoreError(err)
		}
		return errs.New("lock_session_expired",
			"This device holds no live workspace grant. Nothing to relock locally; run daemons unlock first if you meant to relock the guest.", 5)
	}
	_, _, exchangeErr := lock.exchange(ctx, "lock.lock", client.NewLockOperationID(), authority.Device, false,
		func(challenge client.LockChallenge) (map[string]any, error) {
			return client.LockStatusBody(authority.Device, authority.SessionUUID, challenge)
		})
	// A Control Plane that does not admit lock.lock never carried the request to
	// the guest, so nothing was asked to end and the device keeps the grant it
	// already holds. Every other outcome, including an uncertain one, gives the
	// local grant up: this device must not keep an authority it asked to end.
	if errs.Code(exchangeErr) == "lock_protocol_unsupported" {
		fmt.Fprintln(dependencies.ErrorOutput,
			"The workspace guest was not relocked and this device keeps its grant.")
		return exchangeErr
	}
	if err := lock.store.Revoke(lock.baseURL, lock.daemonID); err != nil {
		return lockStoreError(err)
	}
	if exchangeErr != nil {
		fmt.Fprintln(dependencies.ErrorOutput,
			"The local device session was removed. The workspace guest was not relocked.")
		return exchangeErr
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{"workspace": lock.daemonID, "state": "locked"},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output, "Locked %s. Every device grant on that workspace is invalid.\n", lock.daemonName)
	return nil
}

// ---------------------------------------------------------------------------
// status
// ---------------------------------------------------------------------------

func workspaceLockStatus(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	record, readErr := lock.store.Read(lock.baseURL, lock.daemonID, lock.nowMs())
	identity := map[string]any{"pinned": false}
	deviceState := map[string]any{"unlocked": false, "expires_at": nil}
	if readErr == nil {
		identity = map[string]any{
			"pinned":       true,
			"pin":          record.IdentityPin,
			"confirmation": string(record.Confirmation),
		}
		if record.Grant != nil {
			deviceState = map[string]any{"unlocked": true, "expires_at": lockTime(record.Grant.ExpiresAtMs)}
		}
	} else if !errors.Is(readErr, credentials.ErrLockPinUnknown) {
		return lockStoreError(readErr)
	}

	// Guest state comes from the guest, never from central metadata. Without a
	// live device grant there is nothing to sign a status request with, and
	// this Control Plane does not yet admit lock.status either, so the honest
	// answer is unknown rather than a value derived from something else.
	guest := map[string]any{"state": "unknown", "reason": "lock_status_unavailable"}
	if authority, live, authErr := lock.authority(); authErr == nil && live {
		result, _, exchangeErr := lock.exchange(ctx, "lock.status", client.NewLockOperationID(), authority.Device, false,
			func(challenge client.LockChallenge) (map[string]any, error) {
				return client.LockStatusBody(authority.Device, authority.SessionUUID, challenge)
			})
		if exchangeErr == nil {
			guest = client.ReadLockStatusResult(result)
		} else {
			guest = map[string]any{"state": "unknown", "reason": errs.Code(exchangeErr)}
		}
	}

	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{
				"workspace": lock.daemonID,
				"identity":  identity,
				"device":    deviceState,
				"guest":     guest,
			},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output, "Workspace lock for %s\n", lock.daemonName)
	if pinned, _ := identity["pinned"].(bool); pinned {
		fmt.Fprintf(dependencies.Output, "  Guest identity  pinned (%s) %s\n", identity["confirmation"], identity["pin"])
	} else {
		fmt.Fprintln(dependencies.Output, "  Guest identity  not pinned on this device")
	}
	if unlocked, _ := deviceState["unlocked"].(bool); unlocked {
		fmt.Fprintf(dependencies.Output, "  This device     unlocked until %s\n", deviceState["expires_at"])
	} else {
		fmt.Fprintln(dependencies.Output, "  This device     locked")
	}
	fmt.Fprintf(dependencies.Output, "  Guest state     %s\n", guest["state"])
	return nil
}

// ---------------------------------------------------------------------------
// setup, change and recover: two exchanges with one save-confirm between them.
// ---------------------------------------------------------------------------

func enrollWorkspaceLock(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	next, err := readNewLockSecret(dependencies)
	if err != nil {
		return err
	}
	body, err := client.LockSetupBody(next)
	if err != nil {
		return err
	}
	return runLockRotation(ctx, daemonArgument, "lock.setup", body, options, dependencies,
		"Workspace lock configured. Store the recovery phrase now: it is shown once and the platform cannot retrieve it.")
}

func changeWorkspaceLock(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	current, err := readLockSecret(dependencies, "Current PIN: ")
	if err != nil {
		return err
	}
	next, err := readNewLockSecret(dependencies)
	if err != nil {
		return err
	}
	body, err := client.LockChangeBody(current, next)
	if err != nil {
		return err
	}
	return runLockRotation(ctx, daemonArgument, "lock.change", body, options, dependencies,
		"Workspace PIN changed. Every device grant was invalidated and a new recovery phrase replaced the old one.")
}

func recoverWorkspaceLock(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	entered, err := readHiddenValue(dependencies, "Recovery phrase: ")
	if err != nil {
		return err
	}
	phrase, err := client.NormalizeLockRecoveryPhrase(entered)
	if err != nil {
		return err
	}
	next, err := readNewLockSecret(dependencies)
	if err != nil {
		return err
	}
	body, err := client.LockRecoverBody(phrase, next)
	if err != nil {
		return err
	}
	return runLockRotation(ctx, daemonArgument, "lock.recover", body, options, dependencies,
		"Workspace lock recovered. The old recovery phrase is consumed and a new one replaced it.")
}

// runLockRotation performs the begin step, shows the guest's one-time recovery
// phrase, requires an explicit saved confirmation, and only then commits with
// the confirm step on the same operation UUID and device key.
func runLockRotation(ctx context.Context, daemonArgument, action string, body map[string]any,
	options globalOptions, dependencies Dependencies, success string,
) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	device, err := client.NewLockDeviceKey()
	if err != nil {
		return err
	}
	operation := client.NewLockOperationID()
	begin, _, err := lock.exchange(ctx, action, operation, device, false,
		func(client.LockChallenge) (map[string]any, error) { return body, nil })
	// The staged secrets are dropped as soon as the frame is sealed.
	for key := range body {
		delete(body, key)
	}
	if err != nil {
		return err
	}
	pending, err := client.ReadLockRotationResult(begin)
	if err != nil {
		return err
	}
	// Displayed once, never written to a file, never copied automatically and
	// never repeated by a later status query.
	fmt.Fprintf(dependencies.ErrorOutput, "Recovery phrase (shown once): %s\n", client.GroupLockRecoveryPhrase(pending.Phrase))
	fmt.Fprintln(dependencies.ErrorOutput, "Write it down now. Re-enter it to confirm you saved it.")
	entered, err := readHiddenValue(dependencies, "Recovery phrase: ")
	if err != nil {
		return err
	}
	confirmed, err := client.NormalizeLockRecoveryPhrase(entered)
	if err != nil || confirmed != pending.Phrase {
		return errs.New("lock_setup_unconfirmed",
			"The phrase did not match, so nothing was committed. The workspace stays locked; start the operation again for a fresh phrase.", 2)
	}
	confirmBody, err := client.LockConfirmBody(pending.SetupUUID, pending.ConfirmationNonce, confirmed)
	if err != nil {
		return err
	}
	if _, _, err := lock.exchange(ctx, action, operation, device, false,
		func(client.LockChallenge) (map[string]any, error) { return confirmBody, nil }); err != nil {
		return err
	}
	// The device key that ran a rotation is not a grant: rotation invalidates
	// every grant, so this device must unlock again like any other.
	if err := lock.store.Revoke(lock.baseURL, lock.daemonID); err != nil {
		return lockStoreError(err)
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{"workspace": lock.daemonID, "state": "locked", "action": action},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintln(dependencies.Output, success)
	return nil
}

// ---------------------------------------------------------------------------
// pair
// ---------------------------------------------------------------------------

func pairWorkspaceLock(ctx context.Context, daemonArgument string, forget bool, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	if forget {
		if err := lock.store.Unpin(lock.baseURL, lock.daemonID); err != nil {
			return lockStoreError(err)
		}
		fmt.Fprintf(dependencies.Output, "Forgot the pinned identity and any device grant for %s.\n", lock.daemonName)
		return nil
	}
	// An identity probe sends no request frame at all, so no secret and no
	// device key are exposed while the user compares the pin.
	challenge, err := lock.api.ReadWorkspaceLockIdentity(ctx, lock.daemonID, client.NewLockOperationID(), lock.nowMs())
	if err != nil {
		return err
	}
	pin := challenge.IdentityPin()
	record, readErr := lock.store.Read(lock.baseURL, lock.daemonID, lock.nowMs())
	if readErr == nil && record.IdentityPin == pin && record.Matches(credentials.LockScope{
		OrganizationUUID: challenge.OrganizationUUID, AssignmentGeneration: challenge.AssignmentGeneration,
	}) {
		fmt.Fprintf(dependencies.Output, "%s already pins this guest identity: %s\n", lock.daemonName, pin)
		return nil
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Guest identity offered by %s:\n  %s\n", lock.daemonName, pin)
	if readErr == nil {
		fmt.Fprintf(dependencies.ErrorOutput, "This differs from the identity already pinned on this device:\n  %s\nAccept it only if you compared it on an already trusted device or you know the workspace was reassigned.\n", record.IdentityPin)
	} else {
		fmt.Fprintln(dependencies.ErrorOutput, "Compare it with an already trusted device before accepting it.")
	}
	answer, err := readHiddenValue(dependencies, "Type the last four characters of the identity to accept it: ")
	if err != nil {
		return err
	}
	if len(pin) < 4 || strings.TrimSpace(answer) != pin[len(pin)-4:] {
		return errs.New("lock_identity_unpinned", "The identity was not accepted. Nothing was stored.", 5)
	}
	scope := credentials.LockScope{
		BaseURL:              lock.baseURL,
		OrganizationUUID:     challenge.OrganizationUUID,
		WorkspaceUUID:        lock.daemonID,
		AssignmentGeneration: challenge.AssignmentGeneration,
	}
	if err := lock.store.Repair(scope, pin, credentials.LockPinManualComparison); err != nil {
		return lockStoreError(err)
	}
	fmt.Fprintf(dependencies.Output, "Pinned the guest identity for %s. Any earlier device grant was discarded.\n", lock.daemonName)
	return nil
}

// ---------------------------------------------------------------------------
// Pending exchanges: what this device may open, and the two the engineer drives.
// ---------------------------------------------------------------------------

// workspaceLockExchanges reports the exchanges waiting on this actor. It reads
// state only: nothing here opens an exchange or touches a factor.
func workspaceLockExchanges(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	view, err := lock.api.LockExchanges(ctx, lock.daemonID)
	if err != nil {
		return err
	}
	data := view.Data
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{"workspace": lock.daemonID, "lock_state": data.Lock.State,
				"is_owner": data.Actor.IsOwner, "is_assignee": data.Actor.IsAssignee,
				"handoff_pending": data.Handoff != nil, "replacement_pending": data.Replacement != nil},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output, "Lock state: %s\n", data.Lock.State)
	if data.Handoff != nil {
		successor := "unassigned"
		if data.Handoff.SuccessorMembershipUUID != nil {
			successor = *data.Handoff.SuccessorMembershipUUID
		}
		fmt.Fprintf(dependencies.Output, "A reassignment to %s is waiting for your approval. Run daemons lock handoff %s.\n",
			successor, lock.daemonName)
	}
	if data.Replacement != nil {
		fmt.Fprintf(dependencies.Output, "An organization key replacement (revision %d) is waiting for your authorization. Run daemons lock authorize-replacement %s.\n",
			data.Replacement.NewKeyRevision, lock.daemonName)
	}
	if data.Handoff == nil && data.Replacement == nil {
		fmt.Fprintln(dependencies.Output, "Nothing is waiting for you on this workspace.")
	}
	return nil
}

// approveWorkspaceHandoff approves the reassignment the platform is running,
// with the engineer's own factor. The scope is the Control Plane's description
// of that operation, checked against the guest's verified challenge.
func approveWorkspaceHandoff(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	view, err := lock.api.LockExchanges(ctx, lock.daemonID)
	if err != nil {
		return err
	}
	if view.Data.Handoff == nil {
		return errs.New("lock_handoff_unavailable",
			"There is no reassignment waiting for this workspace to be handed over.", 5)
	}
	secret, phrase, err := readEngineerFactor(dependencies)
	if err != nil {
		return err
	}
	device, err := client.NewLockDeviceKey()
	if err != nil {
		return err
	}
	scope := view.Data.Handoff
	// The ticket is minted for the reassignment being approved, because the guest checks that
	// the operation it was admitted under is the one the sealed scope names.
	result, _, err := lock.exchange(ctx, "lock.handoff", scope.OperationUUID, device, false,
		func(challenge client.LockChallenge) (map[string]any, error) {
			return client.LockHandoffBody(secret, phrase, scope, challenge)
		})
	secret, phrase = "", ""
	if err != nil {
		return err
	}
	if err := client.ReadLockDecisionResult(result, "lock.handoff"); err != nil {
		return err
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{"workspace": lock.daemonID, "operation": scope.OperationUUID, "state": "approved"},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output, "Approved the handover of %s. The platform can finish the reassignment now.\n", lock.daemonName)
	return nil
}

// authorizeWorkspaceReplacement authorizes the Owner's pending organization key
// replacement. The confirmation code comes from the Owner directly, so this
// device is agreeing with a person, not with the platform.
func authorizeWorkspaceReplacement(ctx context.Context, daemonArgument string, options globalOptions, dependencies Dependencies) error {
	lock, err := newLockContext(ctx, daemonArgument, options, dependencies)
	if err != nil {
		return err
	}
	view, err := lock.api.LockExchanges(ctx, lock.daemonID)
	if err != nil {
		return err
	}
	if view.Data.Replacement == nil {
		return errs.New("lock_replacement_unavailable",
			"There is no organization key replacement waiting for this workspace.", 5)
	}
	nonce, err := readHiddenValue(dependencies, "Confirmation code from the Owner: ")
	if err != nil {
		return err
	}
	secret, phrase, err := readEngineerFactor(dependencies)
	if err != nil {
		return err
	}
	device, err := client.NewLockDeviceKey()
	if err != nil {
		return err
	}
	pending := view.Data.Replacement
	result, _, err := lock.exchange(ctx, "lock.organization.replace", client.NewLockOperationID(), device, false,
		func(client.LockChallenge) (map[string]any, error) {
			return client.LockReplacementBody(secret, phrase, nonce, pending)
		})
	secret, phrase, nonce = "", "", ""
	if err != nil {
		return err
	}
	if err := client.ReadLockDecisionResult(result, "lock.organization.replace"); err != nil {
		return err
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": map[string]any{"workspace": lock.daemonID, "organization_key_revision": pending.NewKeyRevision,
				"state": "authorized"},
			"meta": map[string]any{},
		})
		return nil
	}
	fmt.Fprintf(dependencies.Output, "Authorized the organization key replacement on %s. The Owner can confirm it now.\n", lock.daemonName)
	return nil
}

// readEngineerFactor takes exactly one factor at a hidden prompt. An empty PIN
// means the engineer is using the recovery phrase instead.
func readEngineerFactor(dependencies Dependencies) (client.LockSecret, string, error) {
	value, err := readHiddenValue(dependencies, "Workspace PIN (leave empty to use the recovery phrase): ")
	if err != nil {
		return "", "", err
	}
	if value != "" {
		secret := client.LockSecret(value)
		if !secret.Valid() {
			return "", "", errs.New("usage_error", "A PIN is exactly four or six digits.", 2)
		}
		return secret, "", nil
	}
	phrase, err := readHiddenValue(dependencies, "Recovery phrase: ")
	if err != nil {
		return "", "", err
	}
	if phrase == "" {
		return "", "", errs.New("usage_error", "Enter either the workspace PIN or the recovery phrase.", 2)
	}
	return "", phrase, nil
}
