package app

import (
	"context"
	"fmt"
	"strings"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const repositoryPushUsage = "Usage: daemons push list DAEMON [--cursor UUID] | daemons push show DAEMON REQUEST_UUID. Push approval is browser-only."

// A subdispatcher keeps push operations separate from the root's two-word
// command matching. No bearer-based approval command is registered.
func repositoryPush(ctx context.Context, args []string, options globalOptions, deps Dependencies) error {
	if helpRequested(args) || (len(args) == 2 && helpRequested(args[1:])) {
		fmt.Fprintln(deps.Output, repositoryPushUsage)
		return nil
	}
	usage := func() error { return errs.New("usage_error", repositoryPushUsage, 2) }
	if len(args) < 2 || args[1] == "" || strings.HasPrefix(args[1], "-") {
		return usage()
	}
	cursor, requestID := "", ""
	switch args[0] {
	case "list":
		if len(args) != 2 && len(args) != 4 {
			return usage()
		}
		if len(args) == 4 {
			if args[2] != "--cursor" || !uuidPattern.MatchString(args[3]) {
				return usage()
			}
			cursor = args[3]
		}
	case "show":
		if len(args) != 3 || !uuidPattern.MatchString(args[2]) {
			return usage()
		}
		requestID = args[2]
	default:
		return usage()
	}
	api, _, _, err := authenticatedClient(options, deps)
	if err != nil {
		return err
	}
	daemonID, err := resolveDaemonID(ctx, api, args[1])
	if err != nil {
		return err
	}
	seen := map[string]bool{}
	for pageNumber := 0; pageNumber < 50; pageNumber++ {
		if seen[cursor] {
			return errs.New("invalid_response", "The repository cursor repeated.", 8)
		}
		seen[cursor] = true
		page, err := api.ListRepositoryPushes(ctx, daemonID, cursor)
		if err != nil {
			return err
		}
		if args[0] == "list" {
			if options.JSON {
				writeCanonicalJSON(deps.Output, page.Raw)
				return nil
			}
			writer := tabwriter.NewWriter(deps.Output, 0, 4, 2, ' ', 0)
			fmt.Fprintln(writer, "REQUEST\tSTATE\tEXPIRES")
			for _, item := range page.Data {
				fmt.Fprintf(writer, "%s\t%s\t%s\n", item.RequestUUID, item.State, item.ExpiresAt)
			}
			if err := writer.Flush(); err != nil {
				return err
			}
			if page.NextCursor != nil {
				fmt.Fprintf(deps.Output, "Next cursor: %s\n", *page.NextCursor)
			}
			return nil
		}
		for _, item := range page.Data {
			if !strings.EqualFold(item.RequestUUID, requestID) {
				continue
			}
			if options.JSON {
				writeJSON(deps.Output, map[string]any{"data": item})
				return nil
			}
			fmt.Fprintf(deps.Output, "Request: %s\nState: %s\nExpires: %s\nStatistics: %s\n", item.RequestUUID, item.State, item.ExpiresAt, item.StatsStatus)
			if item.StatsStatus == "complete" {
				fmt.Fprintf(deps.Output, "Commits: %d\nFiles changed: %d\nInsertions: %d\nDeletions: %d\n", *item.CommitCount, *item.FilesChanged, *item.Insertions, *item.Deletions)
			}
			if item.OutcomeCode != nil {
				fmt.Fprintf(deps.Output, "Outcome: %s\n", *item.OutcomeCode)
			}
			return nil
		}
		if page.NextCursor == nil {
			return errs.New("not_found", "The repository request was not found.", 4)
		}
		cursor = *page.NextCursor
	}
	return errs.New("repository_scan_limit", "Request lookup exceeded 50 pages. Inspect the paginated push list.", 8)
}
