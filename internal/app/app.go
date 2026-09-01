package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"golang.org/x/term"
)

const help = `Usage: daemons <command> [options]

Commands:
  login [--scope SCOPE] [--lifetime 7d]
  logout
  whoami
  capabilities
  servers list
  servers show ID
  list | ls | daemons list
  show ID | daemons show ID
  start|stop|restart ID
  operations show ID
  attach DAEMON [--session NAME]
  upload DAEMON PATH...

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
