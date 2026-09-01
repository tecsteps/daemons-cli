package app

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const operationsListUsage = "Usage: daemons operations list [--limit N]"

func listOperations(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, operationsListUsage)
		return nil
	}
	limit := 0
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != "--limit" {
			return errs.New("usage_error", operationsListUsage, 2)
		}
		if index+1 >= len(arguments) {
			return errs.New("usage_error", "--limit requires a value.", 2)
		}
		parsed, err := strconv.Atoi(arguments[index+1])
		if err != nil || parsed < 1 || parsed > 200 {
			return errs.New("usage_error", "--limit must be a whole number between 1 and 200.", 2)
		}
		limit = parsed
		index++
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.ListOperations(ctx, limit)
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tTYPE\tSTATUS\tRESOURCE\tUPDATED")
	for _, current := range result.Data {
		resource := "-"
		if current.Resource != nil && current.Resource.ID != "" {
			resource = current.Resource.Type + " " + current.Resource.ID
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", current.ID, current.Type, current.Status, resource, current.UpdatedAt)
	}
	return writer.Flush()
}

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

func sortedKeys(values map[string]any) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
