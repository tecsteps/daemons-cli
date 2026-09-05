package app

import (
	"context"
	"errors"
	"fmt"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/operation"
	"os"
	"strings"
	"time"
)

func ssh(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons ssh enable|disable|keys ...")
		return runResult{}
	}
	if len(args) == 0 {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh enable|disable|keys ...", 2))
	}
	switch args[0] {
	case "enable":
		return sshEnable(ctx, args[1:], opt, d)
	case "disable":
		return sshDisable(ctx, args[1:], opt, d)
	case "keys":
		return sshKeys(ctx, args[1:], opt, d)
	}
	return runResultFor(errs.New("usage_error", "Usage: daemons ssh enable|disable|keys ...", 2))
}
func adjacentPublicKey(path string) (string, error) {
	if path == "" {
		return "", errors.New("--identity is required")
	}
	p := path + ".pub"
	info, err := os.Lstat(p)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return "", errors.New("public key must be a regular file")
	}
	b, err := os.ReadFile(p)
	if err != nil {
		return "", err
	}
	v := strings.TrimSpace(string(b))
	if v == "" || strings.ContainsAny(v, "\r\n") {
		return "", errors.New("public key must be one line")
	}
	return v, nil
}
func sshEnable(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	f, e := parseMutationFlags(args, []string{"--identity"}, "Usage: daemons ssh enable DAEMON --identity PATH [--wait]", opt, d)
	if e != nil {
		return runResultFor(e)
	}
	if len(f.Positionals) != 1 || f.Values["--identity"] == "" {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh enable DAEMON --identity PATH [--wait]", 2))
	}
	if e = ensureIdempotencyKey(&f, opt, d); e != nil {
		return runResultFor(e)
	}
	// Enabling is not useful until reconciliation completes.
	f.Wait = true
	key, e := adjacentPublicKey(f.Values["--identity"])
	if e != nil {
		return runResultFor(errs.New("ssh_key_unreadable", "Could not read the adjacent public key: "+e.Error(), 2))
	}
	api, _, _, e := authenticatedClient(opt, d)
	if e != nil {
		return runResultFor(e)
	}
	r, e := api.AddSSHKey(ctx, f.Positionals[0], key, f.IdempotencyKey)
	if e != nil {
		return mutationFailure(e, opt, d, reconcileGuide{Check: "daemons ssh keys list " + f.Positionals[0]})
	}
	out := finishOperation(ctx, api, r, f, opt, d, reconcileGuide{Check: "daemons ssh keys list " + f.Positionals[0]})
	if out.err != nil {
		return out
	}
	access, e := api.SSH(ctx, f.Positionals[0])
	if e != nil {
		return runResultFor(e)
	}
	if !access.Data.Enabled || !access.Data.Reconciled || access.Data.HostKey == "" {
		return runResultFor(errs.New("ssh_not_ready", "SSH was not exported as enabled and reconciled.", 1))
	}
	return out
}
func sshDisable(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	f, e := parseMutationFlags(args, nil, "Usage: daemons ssh disable DAEMON [--wait]", opt, d)
	if e != nil {
		return runResultFor(e)
	}
	if len(f.Positionals) != 1 {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh disable DAEMON [--wait]", 2))
	}
	if e = ensureIdempotencyKey(&f, opt, d); e != nil {
		return runResultFor(e)
	}
	api, _, _, e := authenticatedClient(opt, d)
	if e != nil {
		return runResultFor(e)
	}
	r, e := api.DisableSSH(ctx, f.Positionals[0], f.IdempotencyKey)
	if e != nil {
		return mutationFailure(e, opt, d, reconcileGuide{})
	}
	return finishOperation(ctx, api, r, f, opt, d, reconcileGuide{})
}
func sshKeys(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	if len(args) < 2 {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh keys list|remove DAEMON [FINGERPRINT]", 2))
	}
	api, _, _, e := authenticatedClient(opt, d)
	if e != nil {
		return runResultFor(e)
	}
	switch args[0] {
	case "list":
		if len(args) != 2 {
			return runResultFor(errs.New("usage_error", "Usage: daemons ssh keys list DAEMON", 2))
		}
		r, e := api.SSH(ctx, args[1])
		if e != nil {
			return runResultFor(e)
		}
		if opt.JSON {
			writeCanonicalJSON(d.Output, r.Raw)
		} else {
			for _, k := range r.Data.Keys {
				fmt.Fprintf(d.Output, "%s\t%s\n", k.Fingerprint, k.ID)
			}
		}
		return runResult{}
	case "remove":
		if len(args) != 3 {
			return runResultFor(errs.New("usage_error", "Usage: daemons ssh keys remove DAEMON FINGERPRINT", 2))
		}
		r, e := api.SSH(ctx, args[1])
		if e != nil {
			return runResultFor(e)
		}
		id := ""
		for _, k := range r.Data.Keys {
			if k.Fingerprint == args[2] {
				id = k.ID
			}
		}
		if id == "" {
			return runResultFor(errs.New("not_found", "SSH key fingerprint was not found.", 4))
		}
		f := mutationFlags{WaitTimeout: operationDefaultTimeout()}
		if e = ensureIdempotencyKey(&f, opt, d); e != nil {
			return runResultFor(e)
		}
		op, e := api.RemoveSSHKey(ctx, args[1], id, f.IdempotencyKey)
		if e != nil {
			return mutationFailure(e, opt, d, reconcileGuide{})
		}
		return finishOperation(ctx, api, op, f, opt, d, reconcileGuide{})
	}
	return runResultFor(errs.New("usage_error", "Usage: daemons ssh keys list|remove ...", 2))
}
func operationDefaultTimeout() time.Duration { return operation.DefaultTimeout }
