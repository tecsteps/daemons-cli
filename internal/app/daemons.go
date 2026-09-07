package app

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

var uuidPattern = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

const spawnUsage = "Usage: daemons create NAME --size SIZE --variant VARIANT --agent AGENT --assigned-user ID --creation-team ID [--team ID] [--accepted-offer ID] [--source empty|payload] [--repo URL --branch BRANCH] [--wait] [--wait-timeout DURATION] [--idempotency-key KEY]"

const destroyUsage = "Usage: daemons destroy ID [--etag ETAG] [--wait] [--wait-timeout DURATION] [--idempotency-key KEY]"

const waitTimeoutHelp = "  --wait-timeout examples: 1s, 10m; bare numbers mean seconds."

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
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSTATUS\tAGENT\tATTACH")
	for _, daemon := range result.Data {
		attachState := "ready"
		if daemon.Status != "running" {
			attachState = "unavailable"
		}
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", daemon.Name, daemon.Status, daemon.PrimaryAgent, attachState)
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
	fmt.Fprintf(dependencies.Output, "ID: %s\nName: %s\nStatus: %s\nPrimary agent: %s\n", daemon.ID, daemon.Name, daemon.Status, daemon.PrimaryAgent)
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
	return operationHandler("retry")(ctx, arguments, options, dependencies)
}

func lifecycleDaemon(ctx context.Context, action string, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	originalArguments := append([]string(nil), arguments...)
	usage := "Usage: daemons " + action + " ID [--etag ETAG] [--wait] [--wait-timeout DURATION] [--idempotency-key KEY]"
	if action == "restart" {
		usage += " [--force]"
	}
	if action == "resize" {
		usage += " --size SIZE --accepted-offer UUID"
	}
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		fmt.Fprintln(dependencies.Output, waitTimeoutHelp)
		return runResult{}
	}
	force := false
	if action == "restart" {
		filtered := []string{}
		for _, arg := range arguments {
			if arg == "--force" {
				force = true
			} else {
				filtered = append(filtered, arg)
			}
		}
		arguments = filtered
	}
	valueFlags := []string{"--etag"}
	if action == "resize" {
		valueFlags = append(valueFlags, "--size", "--accepted-offer")
	}
	flags, err := parseMutationFlags(arguments, valueFlags, usage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) > 1 && action == "stop" {
		return bulkDaemons(ctx, action, flags, options, dependencies)
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
	if action == "resize" && (!validSize(flags.Values["--size"]) || !uuidPattern.MatchString(flags.Values["--accepted-offer"])) {
		return runResultFor(errs.New("usage_error", "Resize requires --size small|medium|large and --accepted-offer UUID.", 2))
	}
	etag, err := daemonETag(ctx, api, daemonID, flags.Values["--etag"])
	if err != nil {
		return runResultFor(err)
	}
	body := map[string]any{}
	if action == "restart" {
		body["force"] = force
	}
	if action == "resize" {
		body["size"] = flags.Values["--size"]
		body["accepted_offer_id"] = flags.Values["--accepted-offer"]
	}
	guide := reconcileGuide{
		Check:          "daemons show " + daemonID,
		Replay:         replayCommand(action, originalArguments) + " --etag " + shellArgument(etag),
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.LifecycleDaemonWithOptions(ctx, daemonID, action, etag, flags.IdempotencyKey, body)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	return finishOperation(ctx, api, result, flags, options, dependencies, guide)
}

func spawnDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, spawnUsage)
		fmt.Fprintln(dependencies.Output, waitTimeoutHelp)
		return runResult{}
	}
	for _, arg := range arguments {
		if arg == "--server" || arg == "--disk-quota-gb" {
			return runResultFor(errs.New("server_selection_removed", "Server selection and disk quotas are no longer supported. Use --size and --variant.", 2))
		}
	}
	flags, err := parseMutationFlags(arguments, []string{"--size", "--variant", "--source", "--agent", "--assigned-user", "--creation-team", "--team", "--accepted-offer", "--repo", "--branch", "--payload-file"}, spawnUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) != 1 || flags.Positionals[0] == "" {
		return runResultFor(errs.New("usage_error", spawnUsage, 2))
	}
	spawn := client.SpawnRequest{Name: flags.Positionals[0], PrimaryAgent: flags.Values["--agent"], Size: flags.Values["--size"], Variant: flags.Values["--variant"], Source: flags.Values["--source"], AssignedUserID: flags.Values["--assigned-user"], CreationTeamID: flags.Values["--creation-team"], TeamID: flags.Values["--team"], AcceptedOfferID: flags.Values["--accepted-offer"]}
	if spawn.Source == "" {
		spawn.Source = "empty"
	}
	if !validSize(spawn.Size) || (spawn.Variant != "burstable" && spawn.Variant != "reserved") || spawn.PrimaryAgent == "" || !uuidPattern.MatchString(spawn.AssignedUserID) || !uuidPattern.MatchString(spawn.CreationTeamID) {
		return runResultFor(errs.New("usage_error", spawnUsage, 2))
	}
	for _, id := range []string{spawn.TeamID, spawn.AcceptedOfferID} {
		if id != "" && !uuidPattern.MatchString(id) {
			return runResultFor(errs.New("usage_error", "Team and accepted offer must be UUIDs.", 2))
		}
	}
	if spawn.Source != "empty" && spawn.Source != "payload" {
		return runResultFor(errs.New("usage_error", "--source must be empty or payload.", 2))
	}
	for _, name := range []string{"--repo", "--branch", "--payload-file"} {
		if _, present := flags.Values[name]; present {
			return runResultFor(client.LocalPayloadUnavailable())
		}
	}
	if spawn.Source == "payload" {
		fmt.Fprintln(dependencies.ErrorOutput, "Content stays on your device. The payload deadline is 15 minutes after the target is ready, not during a capacity wait. The API does not yet publish the E4 upload endpoint.")
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}

	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{
		Check:          "daemons list (look for " + spawn.Name + ")",
		Replay:         replayCommand("create", arguments),
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.SpawnDaemon(ctx, spawn, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if !options.JSON {
		fmt.Fprintf(dependencies.Output, "Daemon %s (%s): %s.\n", result.Data.Name, result.Data.ID, result.Data.Status)
	}
	initial := client.OperationEnvelope{Data: result.Meta.Operation, Raw: result.Raw}
	return finishOperation(ctx, api, initial, flags, options, dependencies, guide)
}

func destroyDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, destroyUsage)
		fmt.Fprintln(dependencies.Output, waitTimeoutHelp)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, []string{"--etag"}, destroyUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) > 1 {
		return bulkDaemons(ctx, "delete", flags, options, dependencies)
	}
	if len(flags.Positionals) != 1 {
		return runResultFor(errs.New("usage_error", destroyUsage, 2))
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
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
		Check:          "daemons show " + daemonID + " (a 404 alone does not prove deletion)",
		Replay:         replayCommand("delete", arguments) + " --etag " + shellArgument(etag),
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
	if options.JSON {
		writeMutationError(dependencies, err)
	} else {
		writeError(dependencies, false, err)
	}
	fmt.Fprintln(dependencies.ErrorOutput, "Nothing was destroyed: the daemon changed after its state was read.")
	if current, showErr := api.ShowDaemon(ctx, daemonID); showErr == nil {
		fmt.Fprintf(dependencies.ErrorOutput, "Daemon %s is now %s (ETag %s).\n", current.Data.Name, current.Data.Status, current.ETag)
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Review it, then run: daemons destroy %s\n", daemonID)
	return runResult{code: 1, err: err, reported: true}
}

func validSize(size string) bool { return size == "small" || size == "medium" || size == "large" }

func daemonETag(ctx context.Context, api *client.Client, id, etag string) (string, error) {
	if err := api.Preflight(ctx); err != nil {
		return "", err
	}
	if etag != "" {
		return etag, nil
	}
	current, err := api.ShowDaemon(ctx, id)
	if err != nil {
		return "", err
	}
	if current.ETag == "" {
		return "", errs.New("etag_unavailable", "The API returned no ETag; refusing an unconditional mutation.", 1)
	}
	return current.ETag, nil
}

func renameDaemon(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	const usage = "Usage: daemons rename ID NAME [--etag ETAG] [--idempotency-key KEY]"
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, []string{"--etag"}, usage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if len(flags.Positionals) != 2 {
		return runResultFor(errs.New("usage_error", usage, 2))
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	etag, err := daemonETag(ctx, api, flags.Positionals[0], flags.Values["--etag"])
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{Check: "daemons show " + flags.Positionals[0], Replay: replayCommand("rename", arguments) + " --etag " + shellArgument(etag), IdempotencyKey: flags.IdempotencyKey}
	result, err := api.RenameDaemon(ctx, flags.Positionals[0], flags.Positionals[1], etag, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
	} else {
		fmt.Fprintf(dependencies.Output, "Daemon %s: %s\n", result.Data.ID, result.Data.Name)
	}
	return runResult{}
}

func bulkDaemons(ctx context.Context, action string, flags mutationFlags, options globalOptions, dependencies Dependencies) runResult {
	if action == "delete" {
		return runResultFor(errs.New("confirmation_unavailable", "Bulk deletion requires an API confirmation bound to the complete UUID/revision set, which is not available. Delete each workspace with browser confirmation.", 6))
	}
	if flags.Values["--etag"] != "" {
		return runResultFor(errs.New("usage_error", "A single --etag cannot fence a bulk selection.", 2))
	}
	ids := []string{}
	seen := map[string]bool{}
	for _, id := range flags.Positionals {
		if !uuidPattern.MatchString(id) {
			return runResultFor(errs.New("usage_error", "Bulk actions require exact workspace UUIDs.", 2))
		}
		id = strings.ToLower(id)
		if !seen[id] {
			ids = append(ids, id)
			seen[id] = true
		}
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{Check: "daemons list", Replay: "daemons stop " + strings.Join(ids, " "), IdempotencyKey: flags.IdempotencyKey}
	result, err := api.BulkDaemons(ctx, action, ids, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
	}
	final := runResult{}
	deadline := dependencies.Now().Add(flags.WaitTimeout)
	for _, outcome := range result.Data.Outcomes {
		if !options.JSON {
			fmt.Fprintf(dependencies.Output, "%s: %s", outcome.DaemonID, outcome.Status)
			if outcome.OperationID != nil {
				fmt.Fprintf(dependencies.Output, " (operation %s)", *outcome.OperationID)
			}
			if outcome.Code != nil {
				fmt.Fprintf(dependencies.Output, " [%s]", *outcome.Code)
			}
			fmt.Fprintln(dependencies.Output)
		}
		if outcome.Status == "failed" {
			if final.code == 0 {
				final = runResult{code: 1, reported: true}
			}
			continue
		}
		if flags.Wait && outcome.OperationID != nil {
			remaining := deadline.Sub(dependencies.Now())
			if remaining <= 0 {
				return runResultFor(errs.New("wait_timeout", "Bulk polling timed out; accepted operations continue. Inspect each operation ID.", 8))
			}
			current, err := api.ShowOperation(ctx, *outcome.OperationID)
			if err != nil {
				return runResultFor(err)
			}
			childFlags := flags
			childFlags.WaitTimeout = remaining
			child := finishOperation(ctx, api, current, childFlags, options, dependencies, guide)
			if child.code != 0 {
				final = child
			}
			if ctx.Err() != nil || child.code == 8 {
				return child
			}
		}
	}
	return final
}
