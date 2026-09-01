package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"golang.org/x/term"
)

const help = `Usage: daemons <command> [options]

Commands:
  login [--scope SCOPE] [--lifetime 7d] | login --token-stdin
  logout
  whoami
  capabilities
  servers list
  servers show ID
  list | ls | daemons list
  show ID | daemons show ID
  spawn NAME --server SERVER [--agent AGENT] [--disk-quota-gb N]
  start|stop|restart|retry ID
  destroy ID [--etag ETAG]
  operations list [--limit N]
  operations show ID
  attach DAEMON [--session NAME]
  upload DAEMON PATH...
  task run DAEMON (PROMPT | -) [--agent AGENT] [--model MODEL] [--permission-mode MODE]
  task show DAEMON TASK
  task cancel DAEMON TASK
  task list DAEMON [--limit N]
  files list DAEMON [PATH] [--cursor CURSOR] [--limit N] [--all]
  logs DAEMON --source agent|app|daemon|provisioning [--level LEVEL] [--cursor CURSOR] [--limit N]

Mutation options: --idempotency-key KEY --wait --wait-timeout DURATION (examples: 1s, 10m; bare numbers mean seconds)
Global options: --json --quiet --host URL --no-color --request-id ID --version`

type Dependencies struct {
	Input             io.Reader
	Output            io.Writer
	ErrorOutput       io.Writer
	Stdin             *os.File
	Stdout            *os.File
	Environment       map[string]string
	HTTPClient        *http.Client
	Now               func() time.Time
	Sleep             func(context.Context, time.Duration) error
	Version           string
	IsInteractive     func() bool
	NewIdempotencyKey func() (string, error)
	// OpenURL opens a safe verification or approval URL in the user's browser.
	// Device login opens directly; confirmation flows first ask the user.
	OpenURL func(string) error
}

type runResult struct {
	code     int
	err      error
	reported bool
}

func Run(ctx context.Context, arguments []string, dependencies Dependencies) int {
	dependencies = defaults(dependencies)
	commandArguments, options, err := extractGlobalOptions(arguments)
	if err != nil {
		writeError(dependencies, options.JSON, err)
		return errs.ExitCode(err)
	}
	if options.Host == "" {
		options.Host = dependencies.Environment["DAEMONS_HOST"]
	}
	if options.DeprecatedBaseURL {
		fmt.Fprintln(dependencies.ErrorOutput, "Warning: --base-url is deprecated; use --host.")
	}

	if len(commandArguments) == 0 || commandArguments[0] == "help" || commandArguments[0] == "--help" || commandArguments[0] == "-h" {
		fmt.Fprintln(dependencies.Output, help)
		return 0
	}
	if commandArguments[0] == "--version" || commandArguments[0] == "-v" {
		fmt.Fprintln(dependencies.Output, dependencies.Version)
		return 0
	}

	result := dispatch(ctx, commandArguments, options, dependencies)
	if result.err != nil && !result.reported {
		writeError(dependencies, options.JSON, result.err)
	}
	if result.code != 0 || result.err == nil {
		return result.code
	}
	return errs.ExitCode(result.err)
}

func defaults(dependencies Dependencies) Dependencies {
	if dependencies.Input == nil {
		dependencies.Input = os.Stdin
	}
	if dependencies.Output == nil {
		dependencies.Output = os.Stdout
	}
	if dependencies.ErrorOutput == nil {
		dependencies.ErrorOutput = os.Stderr
	}
	if dependencies.Stdin == nil && dependencies.Input == os.Stdin {
		dependencies.Stdin = os.Stdin
	}
	if dependencies.Stdout == nil && dependencies.Output == os.Stdout {
		dependencies.Stdout = os.Stdout
	}
	if dependencies.Environment == nil {
		dependencies.Environment = environmentMap(os.Environ())
	}
	if dependencies.Now == nil {
		dependencies.Now = time.Now
	}
	if dependencies.Sleep == nil {
		dependencies.Sleep = func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if dependencies.Version == "" {
		dependencies.Version = "dev"
	}
	if dependencies.IsInteractive == nil {
		dependencies.IsInteractive = func() bool {
			return dependencies.Stdin != nil && term.IsTerminal(int(dependencies.Stdin.Fd()))
		}
	}
	if dependencies.OpenURL == nil {
		dependencies.OpenURL = openBrowser
	}
	if dependencies.NewIdempotencyKey == nil {
		dependencies.NewIdempotencyKey = func() (string, error) {
			value := make([]byte, 16)
			if _, err := rand.Read(value); err != nil {
				return "", err
			}
			return "cli-" + hex.EncodeToString(value), nil
		}
	}
	return dependencies
}

func openBrowser(target string) error {
	switch runtime.GOOS {
	case "darwin":
		return exec.Command("open", target).Run()
	case "linux":
		return exec.Command("xdg-open", target).Run()
	default:
		return errors.New("no browser opener for this platform")
	}
}

func environmentMap(values []string) map[string]string {
	environment := make(map[string]string, len(values))
	for _, value := range values {
		key, nested, found := strings.Cut(value, "=")
		if found {
			environment[key] = nested
		}
	}
	return environment
}

func runResultFor(err error) runResult {
	return runResult{code: errs.ExitCode(err), err: err}
}
