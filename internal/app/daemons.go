package app

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

func listDaemons(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons list | daemons daemons list")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons list", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.ListDaemons(ctx)
	if err != nil {
		return err
	}
	if options.JSON {
		writeJSON(dependencies.Output, result)
		return nil
	}

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSTATUS\tAGENT\tSERVER\tATTACH")
	for _, daemon := range result.Data {
		attachState := "ready"
		if daemon.Status != "running" {
			attachState = "unavailable"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\t%s\n", daemon.Name, daemon.Status, daemon.PrimaryAgent, daemon.Server.Name, attachState)
	}
	return writer.Flush()
}

func showDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons show ID")
		return nil
	}
	if len(arguments) != 1 {
		return errs.New("usage_error", "Usage: daemons show ID", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.ShowDaemon(ctx, arguments[0])
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}
	daemon := result.Data
	fmt.Fprintf(dependencies.Output, "ID: %s\nName: %s\nStatus: %s\nPrimary agent: %s\nServer: %s\n", daemon.ID, daemon.Name, daemon.Status, daemon.PrimaryAgent, daemon.Server.Name)
	return nil
}

func startDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	return lifecycleDaemon(ctx, "start", arguments, options, dependencies)
}

func stopDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	return lifecycleDaemon(ctx, "stop", arguments, options, dependencies)
}

func restartDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	return lifecycleDaemon(ctx, "restart", arguments, options, dependencies)
}

func lifecycleDaemon(ctx context.Context, action string, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	usage := "Usage: daemons " + action + " ID [--idempotency-key KEY]"
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		return runResult{}
	}
	daemonID, idempotencyKey, err := lifecycleArguments(arguments, usage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	result, err := api.LifecycleDaemon(ctx, daemonID, action, idempotencyKey)
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

func writeOperation(dependencies Dependencies, operation client.Operation) {
	fmt.Fprintf(dependencies.Output, "Operation %s: %s (%s)\n", operation.ID, operation.Status, operation.Type)
}
