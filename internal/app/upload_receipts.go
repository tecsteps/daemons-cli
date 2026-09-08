package app

import (
	"context"
	"fmt"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func uploadReceipt(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	const usage = "Usage: daemons files receipt DAEMON OPERATION"
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		return runResult{}
	}
	if len(arguments) != 2 || arguments[0] == "" || !uuidPattern.MatchString(arguments[1]) {
		return runResultFor(errs.New("usage_error", usage, 2))
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID, err := resolveDaemonID(ctx, api, arguments[0])
	if err != nil {
		return runResultFor(err)
	}
	receipt, err := api.GetUploadReceipt(ctx, daemonID, arguments[1])
	if err != nil {
		return runResultFor(err)
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{"data": receipt, "meta": map[string]any{"operation_uuid": arguments[1]}})
	} else {
		fmt.Fprintf(dependencies.Output, "Upload %s: %s\n", arguments[1], receipt.Status)
	}
	if receipt.Status != "applied" {
		return runResult{code: 8, err: errs.New("upload_outcome_unresolved", "The guest has not confirmed this upload. Do not replay it automatically.", 8), reported: options.JSON}
	}
	return runResult{}
}
