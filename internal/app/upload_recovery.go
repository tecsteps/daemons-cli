package app

import (
	"context"
	"fmt"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const filesRecoverUsage = "Usage: daemons files recover DAEMON"

// recoverUploads resolves every locally recorded upload operation through a
// fresh receipt read. It never resends file bytes: an unresolved operation is
// reported and kept, so a mutation is never replayed on the user's behalf.
func recoverUploads(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, filesRecoverUsage)
		return runResult{}
	}
	if len(arguments) != 1 || arguments[0] == "" {
		return runResultFor(errs.New("usage_error", filesRecoverUsage, 2))
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID, err := resolveDaemonID(ctx, api, arguments[0])
	if err != nil {
		return runResultFor(err)
	}
	staging, err := uploadStaging(options, dependencies, daemonID)
	if err != nil {
		return runResultFor(err)
	}
	pending, err := staging.List()
	if err != nil {
		return runResultFor(err)
	}

	type resolved struct {
		Operation string `json:"operation_uuid"`
		Selector  string `json:"selector"`
		Status    string `json:"status"`
		Path      string `json:"path,omitempty"`
	}
	results := make([]resolved, 0, len(pending))
	unresolved := 0
	var readErr error
	for _, entry := range pending {
		receipt, receiptErr := api.GetUploadReceipt(ctx, daemonID, entry.OperationUUID)
		if receiptErr != nil {
			readErr = receiptErr
			results = append(results, resolved{Operation: entry.OperationUUID, Selector: entry.Selector, Status: "unreadable"})
			unresolved++
			continue
		}
		results = append(results, resolved{Operation: entry.OperationUUID, Selector: entry.Selector, Status: receipt.Status, Path: receipt.Path})
		switch receipt.Status {
		case "applied", "not_found":
			// The outcome is settled either way, so the record can go.
			if removeErr := staging.Remove(entry.OperationUUID); removeErr != nil {
				readErr = removeErr
			}
		default:
			unresolved++
		}
	}

	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{
			"data": results,
			"meta": map[string]any{"pending": len(pending), "unresolved": unresolved, "record": staging.Path()},
		})
	} else {
		for _, result := range results {
			fmt.Fprintf(dependencies.Output, "%s %s %s\n", result.Operation, result.Status, sanitizeText(result.Path))
		}
		if len(results) == 0 && !options.Quiet {
			fmt.Fprintln(dependencies.ErrorOutput, "No pending uploads are recorded for this daemon.")
		}
	}
	if unresolved > 0 {
		return runResult{code: 8, err: errs.New("upload_outcome_unresolved",
			fmt.Sprintf("%d upload operation(s) remain unresolved. Do not replay them automatically.", unresolved), 8), reported: options.JSON}
	}
	if readErr != nil {
		return runResult{code: errs.ExitCode(readErr), err: readErr, reported: options.JSON}
	}
	return runResult{}
}
