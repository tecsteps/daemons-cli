package app

import (
	"context"
	"fmt"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/terminal"
)

func attach(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons attach DAEMON [--session NAME]")
		return nil
	}
	if options.JSON {
		return errs.New("usage_error", "Attach does not support --json.", 2)
	}
	if len(arguments) < 1 {
		return errs.New("usage_error", "Usage: daemons attach DAEMON [--session NAME]", 2)
	}
	daemonArgument := arguments[0]
	session := "main"
	for index := 1; index < len(arguments); index++ {
		if arguments[index] != "--session" || index+1 >= len(arguments) {
			return errs.New("usage_error", "Usage: daemons attach DAEMON [--session NAME]", 2)
		}
		session = arguments[index+1]
		index++
	}
	if !validSession(session) {
		return errs.New("invalid_session", "Session names use only letters, numbers, underscore, and hyphen, up to 64 characters.", 2)
	}
	if dependencies.Stdin == nil || dependencies.Stdout == nil {
		return errs.New("tty_required", "Attach requires interactive stdin and stdout terminals.", 2)
	}
	size, err := terminal.Preflight(dependencies.Stdin, dependencies.Stdout, dependencies.Environment["TERM"])
	if err != nil {
		return err
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	daemon, err := api.ResolveDaemon(ctx, daemonArgument)
	if err != nil {
		return err
	}
	if daemon.Status != "running" {
		return errs.New("daemon_not_running", "The daemon is not running. Start it before attaching.", 1)
	}
	if err := api.Preflight(ctx); err != nil {
		return err
	}

	signals, stopSignals := terminal.WatchSignals()
	defer stopSignals()
	resizes, stopResizes := terminal.WatchResize(dependencies.Stdout)
	defer stopResizes()
	fmt.Fprint(dependencies.Output, terminal.UsageNotice(daemon.Name, session))
	restore, err := terminal.EnterRaw(dependencies.Stdin)
	if err != nil {
		return err
	}
	outcome, attachErr := terminal.Connect(ctx, api, daemon.ID, session, size, terminal.Streams{
		Input:   dependencies.Input,
		Output:  dependencies.Output,
		Resize:  resizes,
		Signals: signals,
	})
	if restoreErr := restore(); restoreErr != nil {
		return errs.New("terminal_restore_failed", restoreErr.Error(), 1)
	}
	if attachErr != nil {
		return attachErr
	}
	if outcome.Detached {
		fmt.Fprintf(dependencies.Output, "\nDetached from %s/%s. The remote session is still running.\n", daemon.Name, session)
	} else if outcome.Replaced {
		fmt.Fprintf(dependencies.Output, "\nDetached: %s/%s was opened elsewhere.\n", daemon.Name, session)
	}
	if outcome.ExitCode != 0 {
		return errs.New("terminal_closed", "The terminal session closed.", outcome.ExitCode)
	}
	return nil
}

func validSession(value string) bool {
	if value == "" || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') || (character >= '0' && character <= '9') || character == '_' || character == '-' {
			continue
		}
		return false
	}
	return true
}
