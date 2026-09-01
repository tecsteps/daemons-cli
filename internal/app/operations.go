package app

import (
	"context"
	"fmt"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

func showOperation(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons operations show ID")
		return runResult{}
	}
	if len(arguments) != 1 {
		return runResultFor(errs.New("usage_error", "Usage: daemons operations show ID", 2))
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	result, err := api.ShowOperation(ctx, arguments[0])
	if err != nil {
		return runResultFor(err)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
	} else {
		writeOperation(dependencies, result.Data)
	}
	return operationResult(result.Data, options.JSON)
}

func operationResult(operation client.Operation, alreadyReported bool) runResult {
	var err error
	switch operation.Status {
	case "failed", "partially_succeeded", "cancelled", "timed_out":
		code := "operation_" + operation.Status
		if operation.ErrorCode != nil && *operation.ErrorCode != "" {
			code = *operation.ErrorCode
		}
		err = errs.NewOperation(code, fmt.Sprintf("Operation %s ended with status %s.", operation.ID, operation.Status), operation.Status, 1)
	case "outcome_unknown":
		err = errs.NewOperation("outcome_unknown", fmt.Sprintf("Operation %s has an unknown outcome; reconcile its resource before retrying.", operation.ID), operation.Status, 8)
	}
	if err == nil {
		return runResult{}
	}
	return runResult{code: errs.ExitCode(err), err: err, reported: alreadyReported}
}
