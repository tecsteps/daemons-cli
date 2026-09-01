package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const spawnUsage = "Usage: daemons spawn NAME --server SERVER [--agent AGENT] [--disk-quota-gb N] [--wait] [--wait-timeout 10m] [--idempotency-key KEY]"

const destroyUsage = "Usage: daemons destroy ID [--etag ETAG] [--wait] [--wait-timeout 10m] [--idempotency-key KEY]"

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
	if result.ETag != "" {
		fmt.Fprintf(dependencies.Output, "ETag: %s\n", result.ETag)
	}
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

func retryDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	return lifecycleDaemon(ctx, "retry", arguments, options, dependencies)
}

func lifecycleDaemon(ctx context.Context, action string, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	usage := "Usage: daemons " + action + " ID [--wait] [--wait-timeout 10m] [--idempotency-key KEY]"
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, nil, usage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) != 1 || flags.Positionals[0] == "" {
		return runResultFor(errs.New("usage_error", usage, 2))
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}
	daemonID := flags.Positionals[0]
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{
		Check:          "daemons show " + daemonID,
		Replay:         "daemons " + action + " " + daemonID,
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.LifecycleDaemon(ctx, daemonID, action, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	return finishOperation(ctx, api, result, flags, options, dependencies, guide)
}

func spawnDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, spawnUsage)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, []string{"--server", "--agent", "--disk-quota-gb"}, spawnUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) != 1 || flags.Positionals[0] == "" {
		return runResultFor(errs.New("usage_error", spawnUsage, 2))
	}
	spawn := client.SpawnRequest{Name: flags.Positionals[0], PrimaryAgent: flags.Values["--agent"]}
	serverReference := flags.Values["--server"]
	if serverReference == "" {
		return runResultFor(errs.New("usage_error", "--server is required: pass the server UUID or its exact name.", 2))
	}
	if quota, present := flags.Values["--disk-quota-gb"]; present {
		parsed, parseErr := strconv.Atoi(quota)
		if parseErr != nil || parsed < 1 {
			return runResultFor(errs.New("usage_error", "--disk-quota-gb must be a whole number of gigabytes of at least 1.", 2))
		}
		spawn.DiskQuotaGB = parsed
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}

	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	spawn.ServerID = serverReference
	if !uuidPattern.MatchString(serverReference) {
		server, resolveErr := api.ResolveServer(ctx, serverReference)
		if resolveErr != nil {
			return runResultFor(resolveErr)
		}
		spawn.ServerID = server.ID
	}

	guide := reconcileGuide{
		Check:          "daemons list (look for " + spawn.Name + ")",
		Replay:         "daemons spawn " + spawn.Name + " --server " + serverReference,
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.SpawnDaemon(ctx, spawn, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if !options.JSON {
		fmt.Fprintf(dependencies.Output, "Daemon %s (%s) %s on server %s.\n", result.Data.Name, result.Data.ID, result.Data.Status, result.Data.Server.Name)
	}
	initial := client.OperationEnvelope{Data: result.Meta.Operation, Raw: result.Raw}
	return finishOperation(ctx, api, initial, flags, options, dependencies, guide)
}

func destroyDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, destroyUsage)
		return runResult{}
	}
	flags, err := lifecycleArguments(arguments, destroyUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID := flags.Positionals[0]
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}

	etag := flags.Values["--etag"]
	if etag == "" {
		current, showErr := api.ShowDaemon(ctx, daemonID)
		if showErr != nil {
			return runResultFor(showErr)
		}
		if current.ETag == "" {
			return runResultFor(errs.New("etag_unavailable", "The Control Plane returned no ETag for this daemon; refusing an unconditional destroy.", 1))
		}
		etag = current.ETag
	}

	guide := reconcileGuide{
		Check:          "daemons show " + daemonID + " (a 404 means it is gone)",
		Replay:         "daemons destroy " + daemonID,
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.DestroyDaemon(ctx, daemonID, etag, flags.IdempotencyKey)
	if err != nil {
		var apiError *errs.APIError
		if errors.As(err, &apiError) && apiError.Status == 412 {
			return destroyPreconditionFailed(ctx, api, daemonID, err, options, dependencies)
		}
		return mutationFailure(err, options, dependencies, guide)
	}
	return finishOperation(ctx, api, result, flags, options, dependencies, guide)
}

// destroyPreconditionFailed explains a 412 by re-fetching the daemon so the
// user sees the state that replaced the one they targeted. Nothing was
// destroyed; the CLI does not resubmit a destroy with a fresh ETag by itself.
func destroyPreconditionFailed(ctx context.Context, api *client.Client, daemonID string, err error, options globalOptions, dependencies Dependencies) runResult {
	writeError(dependencies, options.JSON, err)
	fmt.Fprintln(dependencies.ErrorOutput, "Nothing was destroyed: the daemon changed after its state was read.")
	if current, showErr := api.ShowDaemon(ctx, daemonID); showErr == nil {
		fmt.Fprintf(dependencies.ErrorOutput, "Daemon %s is now %s (ETag %s).\n", current.Data.Name, current.Data.Status, current.ETag)
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Review it, then run: daemons destroy %s\n", daemonID)
	return runResult{code: 1, err: err, reported: true}
}
