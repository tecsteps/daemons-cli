package app

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const logsUsage = "Usage: daemons logs DAEMON --source agent|app|daemon|provisioning [--level LEVEL] [--cursor CURSOR] [--limit N]"

// logSources is the closed set the Control Plane accepts. Anything else is
// refused locally so a typo never reaches the server as a validation error.
var logSources = []string{"agent", "app", "daemon", "provisioning"}

var logLevelPattern = regexp.MustCompile(`^[a-z]{1,16}$`)

// showLogs prints one bounded, server-redacted snapshot. There is no
// --follow: the log event route does not exist yet, and the CLI does not
// fake it by polling.
func showLogs(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, logsUsage)
		return nil
	}
	positionals := []string{}
	source, level, cursor := "", "", ""
	limit := 0
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "--follow", "-f":
			return errs.New("usage_error", "logs --follow is not available: the Control Plane exposes no log event route yet. Rerun with --cursor to read newer lines.", 2)
		case "--source", "--level", "--cursor", "--limit":
			if index+1 >= len(arguments) {
				return errs.New("usage_error", argument+" requires a value.", 2)
			}
			value := arguments[index+1]
			index++
			switch argument {
			case "--source":
				source = value
			case "--level":
				level = value
			case "--cursor":
				cursor = value
			default:
				parsed, err := strconv.Atoi(value)
				if err != nil || parsed < 1 || parsed > 200 {
					return errs.New("usage_error", "--limit must be a whole number between 1 and 200.", 2)
				}
				limit = parsed
			}
		default:
			if strings.HasPrefix(argument, "--") {
				return errs.New("usage_error", logsUsage, 2)
			}
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) != 1 || positionals[0] == "" {
		return errs.New("usage_error", logsUsage, 2)
	}
	if !validLogSource(source) {
		return errs.New("usage_error", "--source is required and must be one of: "+strings.Join(logSources, ", ")+".", 2)
	}
	if level != "" && !logLevelPattern.MatchString(level) {
		return errs.New("usage_error", "--level must be a short lowercase word such as info or error.", 2)
	}

	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	daemonID, err := resolveDaemonID(ctx, api, positionals[0])
	if err != nil {
		return err
	}
	result, err := api.ListLogs(ctx, daemonID, source, level, cursor, limit)
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}
	for _, line := range result.Data {
		timestamp := "-"
		if line.Timestamp != nil && *line.Timestamp != "" {
			timestamp = *line.Timestamp
		}
		fmt.Fprintf(dependencies.Output, "%s %s %s\n", timestamp, strings.ToUpper(line.Level), sanitizeText(line.Message))
	}
	if next := result.Meta.NextCursor; next != nil && *next != "" && !options.Quiet {
		fmt.Fprintf(dependencies.ErrorOutput, "Next: daemons logs %s --source %s --cursor %s\n", positionals[0], source, *next)
	}
	return nil
}

func validLogSource(value string) bool {
	for _, candidate := range logSources {
		if candidate == value {
			return true
		}
	}
	return false
}
