package app

import (
	"fmt"
	"regexp"

	"github.com/tecsteps/daemons-cli/internal/errs"
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

func lifecycleArguments(arguments []string, usage string, options globalOptions, dependencies Dependencies) (string, string, error) {
	identifier := ""
	idempotencyKey := ""
	for index := 0; index < len(arguments); index++ {
		if arguments[index] == "--idempotency-key" {
			if index+1 >= len(arguments) {
				return "", "", errs.New("usage_error", "--idempotency-key requires a value.", 2)
			}
			idempotencyKey = arguments[index+1]
			index++
			continue
		}
		if identifier != "" {
			return "", "", errs.New("usage_error", usage, 2)
		}
		identifier = arguments[index]
	}
	if identifier == "" {
		return "", "", errs.New("usage_error", usage, 2)
	}
	if idempotencyKey == "" {
		if options.JSON || !dependencies.IsInteractive() {
			return "", "", errs.New("idempotency_key_required", "Non-interactive mutations require --idempotency-key.", 2)
		}
		var err error
		idempotencyKey, err = dependencies.NewIdempotencyKey()
		if err != nil {
			return "", "", errs.New("idempotency_key_unavailable", "Could not generate an idempotency key.", 1)
		}
		fmt.Fprintf(dependencies.ErrorOutput, "Idempotency-Key: %s\n", idempotencyKey)
	}
	if !idempotencyKeyPattern.MatchString(idempotencyKey) {
		return "", "", errs.New("invalid_idempotency_key", "Idempotency keys must be 8-128 characters using letters, numbers, dot, underscore, colon, or hyphen.", 2)
	}
	return identifier, idempotencyKey, nil
}
