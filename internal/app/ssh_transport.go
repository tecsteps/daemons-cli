package app

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/terminal"
	xssh "golang.org/x/crypto/ssh"
	"golang.org/x/term"
)

const sshUser = "dr-agent"
const syncDefaultRemote = "workspace/default"

var remotePathPattern = regexp.MustCompile(`^[A-Za-z0-9._/-]+$`)

func sshAlias(id string) string { return "daemon-" + id }

func validHostKey(key string) bool {
	parts := strings.Split(key, " ")
	if len(parts) != 2 || parts[0] != "ssh-ed25519" || strings.ContainsAny(key, "\r\n\t\x00") {
		return false
	}
	keyData, _, _, rest, err := xssh.ParseAuthorizedKey([]byte(key))
	return err == nil && len(rest) == 0 && keyData.Type() == xssh.KeyAlgoED25519
}

func fetchSSHHostKey(ctx context.Context, api *client.Client, id string) (string, error) {
	access, err := api.SSH(ctx, id)
	if err != nil {
		return "", err
	}
	if !access.Data.Enabled || !access.Data.Reconciled || !validHostKey(access.Data.HostKey) {
		return "", errs.New("ssh_host_key_missing", "SSH is not ready or its ed25519 host key is malformed. Enable SSH and retry.", 1)
	}
	return access.Data.HostKey, nil
}

func pinnedHostKey(id, key, base string, env map[string]string) error {
	root, err := sshRoot("", env)
	if err != nil {
		return err
	}
	if err := secureDir(root); err != nil {
		return err
	}
	path := filepath.Join(root, originHash(base), "pins", id)
	if err := secureDir(filepath.Dir(path)); err != nil {
		return err
	}
	prior, err := os.ReadFile(path)
	if err == nil {
		if string(prior) != key+"\n" {
			return errs.New("ssh_host_key_changed", "The workspace host key changed. Verify the replacement independently before removing its local pin at "+path+".", 1)
		}
		return nil
	}
	if !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if errors.Is(err, fs.ErrExist) {
		return pinnedHostKey(id, key, base, env)
	}
	if err != nil {
		return err
	}
	if _, err := file.WriteString(key + "\n"); err != nil {
		file.Close()
		return err
	}
	return file.Close()
}

func sshKnownHosts(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons ssh-known-hosts WORKSPACE-UUID")
		return runResult{}
	}
	if len(args) != 1 || !uuidPattern.MatchString(args[0]) {
		return runResultFor(errs.New("usage_error", "Usage: daemons ssh-known-hosts WORKSPACE-UUID", 2))
	}
	api, base, _, err := authenticatedClient(opt, d)
	if err != nil {
		return runResultFor(err)
	}
	key, err := fetchSSHHostKey(ctx, api, args[0])
	if err != nil {
		return runResultFor(err)
	}
	if err := pinnedHostKey(args[0], key, base, d.Environment); err != nil {
		return runResultFor(err)
	}
	fmt.Fprintf(d.Output, "%s %s\n", sshAlias(args[0]), key)
	return runResult{}
}

func runExternal(ctx context.Context, d Dependencies, name string, args ...string) runResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = d.Input, d.Output, d.ErrorOutput
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return runResult{code: exit.ExitCode()}
		}
		return runResultFor(errs.New("command_unavailable", fmt.Sprintf("Could not start %s: %v", name, err), 1))
	}
	return runResult{}
}

func sshProxyOption(id string) string {
	return "ProxyCommand=" + sshQuote(executablePath()) + " ssh-proxy " + id
}

func sshClientOptions(id, known, identity string) []string {
	options := []string{"-o", sshProxyOption(id), "-o", "UserKnownHostsFile=" + known, "-o", "GlobalKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=yes", "-o", "HostKeyAlias=" + sshAlias(id), "-o", "IdentitiesOnly=yes"}
	if identity != "" {
		options = append(options, "-i", identity)
	}
	return options
}

func withKnownHosts(ctx context.Context, id string, opt globalOptions, d Dependencies, action func(string) runResult) runResult {
	api, base, _, err := authenticatedClient(opt, d)
	if err != nil {
		return runResultFor(err)
	}
	key, err := fetchSSHHostKey(ctx, api, id)
	if err != nil {
		return runResultFor(err)
	}
	if err := pinnedHostKey(id, key, base, d.Environment); err != nil {
		return runResultFor(err)
	}
	dir, err := os.MkdirTemp("", "daemons-ssh-")
	if err != nil {
		return runResultFor(err)
	}
	defer os.RemoveAll(dir)
	known := filepath.Join(dir, "known_hosts")
	if err := os.WriteFile(known, []byte(sshAlias(id)+" "+key+"\n"), 0600); err != nil {
		return runResultFor(err)
	}
	return action(known)
}

func sshShell(ctx context.Context, id string, opt globalOptions, d Dependencies) runResult {
	var savedState *term.State
	ttyOutput := d.Stdout != nil && term.IsTerminal(int(d.Stdout.Fd()))
	if d.Stdin != nil && d.Stdout != nil && term.IsTerminal(int(d.Stdin.Fd())) && term.IsTerminal(int(d.Stdout.Fd())) {
		savedState, _ = term.GetState(int(d.Stdin.Fd()))
	}
	defer func() {
		if ttyOutput {
			if savedState != nil {
				if err := term.Restore(int(d.Stdin.Fd()), savedState); err != nil {
					fmt.Fprintln(d.ErrorOutput, "Warning: SSH terminal restore failed [condition=terminal_restore expected=saved_terminal_state observed=restore_error].")
				}
			}
			_, _ = fmt.Fprint(d.Output, "\x1b[<u")
		}
	}()

	return withKnownHosts(ctx, id, opt, d, func(known string) runResult {
		args := append(sshClientOptions(id, known, ""), sshUser+"@"+sshAlias(id))
		return runExternalSSH(ctx, d, "ssh", args...)
	})
}

func runExternalSSH(ctx context.Context, d Dependencies, name string, args ...string) runResult {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = d.Input, d.Output, d.ErrorOutput
	signals, stopSignals := terminal.WatchSignals()
	defer stopSignals()
	if err := cmd.Start(); err != nil {
		return runResultFor(errs.New("command_unavailable", fmt.Sprintf("Could not start %s: %v", name, err), 1))
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	for {
		select {
		case err := <-done:
			if err == nil {
				return runResult{}
			}
			var exit *exec.ExitError
			if errors.As(err, &exit) {
				return runResult{code: exit.ExitCode()}
			}
			return runResultFor(errs.New("ssh_failed", "The SSH client did not exit cleanly.", 1))
		case signal := <-signals:
			_ = cmd.Process.Signal(signal)
		}
	}
}

type syncOptions struct {
	direction, id, local, remote, identity string
	dryRun, delete                         bool
}

func parseSync(args []string) (syncOptions, error) {
	f := syncOptions{remote: syncDefaultRemote}
	if len(args) < 3 || (args[0] != "push" && args[0] != "pull") {
		return f, errs.New("usage_error", "Usage: daemons sync push|pull WORKSPACE-UUID LOCAL-FOLDER [--remote PATH] [--identity PATH] [--dry-run] [--delete]", 2)
	}
	f.direction, f.id, f.local = args[0], args[1], args[2]
	if !uuidPattern.MatchString(f.id) || f.local == "" {
		return f, errs.New("usage_error", "Sync requires a workspace UUID and local folder.", 2)
	}
	for i := 3; i < len(args); i++ {
		switch args[i] {
		case "--dry-run":
			f.dryRun = true
		case "--delete":
			f.delete = true
		case "--remote", "--identity":
			if i+1 >= len(args) || args[i+1] == "" {
				return f, errs.New("usage_error", "Sync option requires a value: "+args[i], 2)
			}
			i++
			if args[i-1] == "--remote" {
				f.remote = args[i]
			} else {
				f.identity = args[i]
			}
		default:
			return f, errs.New("usage_error", "Unknown sync option: "+args[i], 2)
		}
	}
	if !remotePathPattern.MatchString(f.remote) || strings.HasPrefix(f.remote, "/") || strings.HasPrefix(f.remote, "-") {
		return f, errs.New("invalid_remote_path", "Remote path must be relative to the workspace home.", 2)
	}
	for _, part := range strings.Split(f.remote, "/") {
		if part == "" || part == "." || part == ".." {
			return f, errs.New("invalid_remote_path", "Remote path contains an ambiguous component.", 2)
		}
	}
	return f, nil
}

func syncExclusions() []string {
	return []string{"--filter=:- .gitignore", "--exclude=node_modules/", "--exclude=vendor/"}
}

func syncCommand(ctx context.Context, args []string, opt globalOptions, d Dependencies) runResult {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons sync push|pull WORKSPACE-UUID LOCAL-FOLDER [--remote PATH] [--identity PATH] [--dry-run] [--delete]")
		return runResult{}
	}
	f, err := parseSync(args)
	if err != nil {
		return runResultFor(err)
	}
	if f.direction == "push" {
		info, err := os.Stat(f.local)
		if err != nil || !info.IsDir() {
			return runResultFor(errs.New("local_directory_not_found", "Sync refused: local source must be an existing directory.", 2))
		}
	} else if err := os.MkdirAll(f.local, 0755); err != nil {
		return runResultFor(errs.New("local_directory_unavailable", "Sync refused: cannot create the local destination.", 2))
	}
	if f.identity != "" {
		info, err := os.Stat(f.identity)
		if err != nil || !info.Mode().IsRegular() {
			return runResultFor(errs.New("identity_file_not_found", "Sync refused: --identity must name an existing private key file.", 2))
		}
	}
	if _, err := exec.LookPath("rsync"); err != nil {
		return runResultFor(errs.New("rsync_not_found", "Sync refused: install rsync and retry.", 2))
	}
	if _, err := exec.LookPath("ssh"); err != nil {
		return runResultFor(errs.New("ssh_not_found", "Sync refused: install OpenSSH and retry.", 2))
	}
	return withKnownHosts(ctx, f.id, opt, d, func(known string) runResult {
		sshArgs := sshClientOptions(f.id, known, f.identity)
		parts := append([]string{"ssh"}, sshArgs...)
		for i, p := range parts {
			parts[i] = sshQuote(p)
		}
		rsArgs := append([]string{"-az", "--human-readable", "--progress"}, syncExclusions()...)
		if f.dryRun {
			rsArgs = append(rsArgs, "-n", "--itemize-changes")
		}
		if f.delete {
			rsArgs = append(rsArgs, "--delete")
		}
		if f.direction == "push" && !f.dryRun {
			rsArgs = append(rsArgs, "--rsync-path=mkdir -p "+sshQuote(f.remote)+" && rsync")
		}
		local := strings.TrimRight(f.local, "/") + "/"
		remote := sshUser + "@" + sshAlias(f.id) + ":" + f.remote + "/"
		rsArgs = append(rsArgs, "-e", strings.Join(parts, " "), "--")
		if f.direction == "push" {
			rsArgs = append(rsArgs, local, remote)
		} else {
			rsArgs = append(rsArgs, remote, local)
		}
		return runExternal(ctx, d, "rsync", rsArgs...)
	})
}
