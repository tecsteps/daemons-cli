package app

import (
	"context"
	"fmt"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"io"
	"os/exec"
	"path/filepath"
)

func ide(ctx context.Context, args []string, opt globalOptions, d Dependencies) error {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons ide DAEMON --editor code|cursor|zed|jetbrains [--folder NAME] [--cached]")
		return nil
	}
	filtered := make([]string, 0, len(args))
	cachedFlag := false
	for _, a := range args {
		if a == "--cached" {
			cachedFlag = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	f, e := parseMutationFlags(args, []string{"--editor", "--folder"}, "Usage: daemons ide DAEMON --editor code|cursor|zed|jetbrains [--folder NAME] [--cached]", opt, d)
	if e != nil {
		return e
	}
	cached := cachedFlag
	if len(f.Positionals) != 1 || f.Values["--editor"] == "" {
		return errs.New("usage_error", "Usage: daemons ide DAEMON --editor code|cursor|zed|jetbrains [--folder NAME] [--cached]", 2)
	}
	if !cached {
		if e = sshConfig(ctx, []string{f.Positionals[0]}, opt, d); e != nil {
			return e
		}
	}
	_, base, _, e := authenticatedClient(opt, d)
	if e != nil {
		return e
	}
	_, e = exec.LookPath("ssh")
	if e != nil {
		return errs.New("ssh_client_missing", "System OpenSSH client is required.", 2)
	}
	alias := "dr-" + originHash(base) + "-" + f.Positionals[0]
	preflight := exec.CommandContext(ctx, "ssh", "-G", alias)
	preflight.Stdout = io.Discard
	preflight.Stderr = d.ErrorOutput
	if e = preflight.Run(); e != nil {
		return errs.New("ssh_preflight_failed", "SSH configuration preflight failed.", 1)
	}
	folder := "/root/workspace"
	if f.Values["--folder"] != "" {
		folder = filepath.Join(folder, f.Values["--folder"])
	}
	var cmd *exec.Cmd
	switch f.Values["--editor"] {
	case "code", "cursor":
		cmd = exec.CommandContext(ctx, f.Values["--editor"], "--folder-uri", "vscode-remote://ssh-remote+"+alias+folder)
	case "zed":
		cmd = exec.CommandContext(ctx, "zed", "ssh://"+alias+folder)
	case "jetbrains":
		cmd = exec.CommandContext(ctx, "jetbrains-gateway", "--ssh", alias)
	default:
		return errs.New("usage_error", "--editor must be code, cursor, zed, or jetbrains.", 2)
	}
	cmd.Stdout = d.Output
	cmd.Stderr = d.ErrorOutput
	if e = cmd.Run(); e != nil {
		return errs.New("ide_launch_failed", fmt.Sprintf("Could not open %s.", f.Values["--editor"]), 1)
	}
	return nil
}
