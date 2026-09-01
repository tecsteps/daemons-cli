package app

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/operation"
)

var idempotencyKeyPattern = regexp.MustCompile(`^[A-Za-z0-9._:-]{8,128}$`)

type globalOptions struct {
	JSON              bool
	Quiet             bool
	Host              string
	NoColor           bool
	RequestID         string
	CredentialsFile   string
	DeprecatedBaseURL bool
}

func extractGlobalOptions(arguments []string) ([]string, globalOptions, error) {
	options := globalOptions{}
	command := make([]string, 0, len(arguments))
	for index := 0; index < len(arguments); index++ {
		switch arguments[index] {
		case "--json":
			options.JSON = true
		case "--quiet":
			options.Quiet = true
		case "--no-color":
			options.NoColor = true
		case "--base-url", "--host", "--credentials-file", "--request-id":
			if index+1 >= len(arguments) {
				return nil, options, errs.New("usage_error", arguments[index]+" requires a value.", 2)
			}
			value := arguments[index+1]
			switch arguments[index] {
			case "--credentials-file":
				options.CredentialsFile = value
			case "--request-id":
				options.RequestID = value
			case "--base-url":
				options.Host = value
				options.DeprecatedBaseURL = true
			default:
				options.Host = value
			}
			index++
		default:
			command = append(command, arguments[index])
		}
	}
	return command, options, nil
}

// mutationFlags is the parsed argument set shared by every state-changing
// command: positionals, the idempotency key, and the optional --wait pair.
type mutationFlags struct {
	Positionals    []string
	Values         map[string]string
	IdempotencyKey string
	Wait           bool
	WaitTimeout    time.Duration
}

// parseMutationFlags parses arguments for a mutation. valueFlags names the
// command-specific flags that take a value (for example --server). The
// idempotency key follows the Phase 1 contract: explicit, or generated once
// and announced on stderr in interactive use, or refused (exit 2) otherwise.
func parseMutationFlags(arguments []string, valueFlags []string, usage string, _ globalOptions, _ Dependencies) (mutationFlags, error) {
	flags := mutationFlags{Values: map[string]string{}, WaitTimeout: operation.DefaultTimeout}
	waitTimeout := ""
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		if !strings.HasPrefix(argument, "--") {
			flags.Positionals = append(flags.Positionals, argument)
			continue
		}
		if argument == "--wait" {
			flags.Wait = true
			continue
		}
		takesValue := argument == "--idempotency-key" || argument == "--wait-timeout"
		for _, name := range valueFlags {
			if argument == name {
				takesValue = true
			}
		}
		if !takesValue {
			return flags, errs.New("usage_error", usage, 2)
		}
		if index+1 >= len(arguments) {
			return flags, errs.New("usage_error", argument+" requires a value.", 2)
		}
		value := arguments[index+1]
		index++
		switch argument {
		case "--idempotency-key":
			flags.IdempotencyKey = value
		case "--wait-timeout":
			waitTimeout = value
		default:
			flags.Values[argument] = value
		}
	}
	if waitTimeout != "" {
		parsed, err := parseWaitTimeout(waitTimeout)
		if err != nil || parsed <= 0 {
			return flags, errs.New("usage_error", "--wait-timeout must be positive; use a duration such as 1s or 10m, or a bare number of seconds.", 2)
		}
		flags.WaitTimeout = parsed
	}
	return flags, nil
}

func parseWaitTimeout(value string) (time.Duration, error) {
	if value != "" && strings.IndexFunc(value, func(character rune) bool {
		return character < '0' || character > '9'
	}) == -1 {
		seconds, err := strconv.ParseInt(value, 10, 64)
		if err != nil || seconds <= 0 || seconds > int64((1<<63-1)/time.Second) {
			return 0, errs.New("usage_error", "invalid wait timeout", 2)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	return time.ParseDuration(value)
}

// ensureIdempotencyKey applies the Phase 1 key contract after local argument
// validation, so a usage mistake is reported before a missing key is.
func ensureIdempotencyKey(flags *mutationFlags, options globalOptions, dependencies Dependencies) error {
	if flags.IdempotencyKey == "" {
		if options.JSON || !dependencies.IsInteractive() {
			return errs.New("idempotency_key_required", "Non-interactive mutations require --idempotency-key.", 2)
		}
		var err error
		flags.IdempotencyKey, err = dependencies.NewIdempotencyKey()
		if err != nil {
			return errs.New("idempotency_key_unavailable", "Could not generate an idempotency key.", 1)
		}
		fmt.Fprintf(dependencies.ErrorOutput, "Idempotency-Key: %s\n", flags.IdempotencyKey)
	}
	if !idempotencyKeyPattern.MatchString(flags.IdempotencyKey) {
		return errs.New("invalid_idempotency_key", "Idempotency keys must be 8-128 characters using letters, numbers, dot, underscore, colon, or hyphen.", 2)
	}
	return nil
}

func lifecycleArguments(arguments []string, usage string, options globalOptions, dependencies Dependencies) (mutationFlags, error) {
	flags, err := parseMutationFlags(arguments, []string{"--etag"}, usage, options, dependencies)
	if err != nil {
		return flags, err
	}
	if len(flags.Positionals) != 1 || flags.Positionals[0] == "" {
		return flags, errs.New("usage_error", usage, 2)
	}
	return flags, ensureIdempotencyKey(&flags, options, dependencies)
}
