package app

import (
	"context"
	"fmt"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	filesListUsage = "Usage: daemons files list DAEMON [PATH] [--cursor CURSOR] [--limit N] [--all]"
	// maximumListPages bounds --all so a listing can never turn into an
	// unbounded crawl of a large workspace.
	maximumListPages = 50
)

// listFiles reads a workspace directory inventory. It never fetches file
// content: the canonical read and download routes are not available yet.
func listFiles(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, filesListUsage)
		return nil
	}
	positionals := []string{}
	cursor := ""
	limit := 0
	all := false
	for index := 0; index < len(arguments); index++ {
		argument := arguments[index]
		switch argument {
		case "--all":
			all = true
		case "--cursor", "--limit":
			if index+1 >= len(arguments) {
				return errs.New("usage_error", argument+" requires a value.", 2)
			}
			value := arguments[index+1]
			index++
			if argument == "--cursor" {
				cursor = value
				continue
			}
			parsed, err := strconv.Atoi(value)
			if err != nil || parsed < 1 || parsed > 200 {
				return errs.New("usage_error", "--limit must be a whole number between 1 and 200.", 2)
			}
			limit = parsed
		default:
			if strings.HasPrefix(argument, "--") {
				return errs.New("usage_error", filesListUsage, 2)
			}
			positionals = append(positionals, argument)
		}
	}
	if len(positionals) < 1 || len(positionals) > 2 || positionals[0] == "" {
		return errs.New("usage_error", filesListUsage, 2)
	}
	workspacePath := ""
	if len(positionals) == 2 {
		workspacePath = strings.Trim(positionals[1], "/")
		if !safeRelativeWorkspacePath(workspacePath) {
			return errs.New("unsafe_workspace_path", "PATH must be a plain relative workspace path without . or .. segments.", 2)
		}
	}
	if all && cursor != "" {
		return errs.New("usage_error", "--all starts from the first page; do not combine it with --cursor.", 2)
	}

	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	daemonID, err := resolveDaemonID(ctx, api, positionals[0])
	if err != nil {
		return err
	}

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	if !options.JSON {
		fmt.Fprintln(writer, "TYPE\tSIZE\tMODIFIED\tNAME")
	}
	pages := 0
	for {
		page, err := api.ListFiles(ctx, daemonID, workspacePath, cursor, limit)
		if err != nil {
			_ = writer.Flush()
			return err
		}
		pages++
		if options.JSON {
			writeCanonicalJSON(dependencies.Output, page.Raw)
		} else {
			for _, entry := range page.Data {
				fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", entry.Type, entry.Size, time.Unix(entry.MTime, 0).UTC().Format(time.RFC3339), sanitizeText(entry.Name))
			}
		}
		next := ""
		if page.Meta.NextCursor != nil {
			next = *page.Meta.NextCursor
		}
		if next == "" {
			break
		}
		if !all {
			_ = writer.Flush()
			if !options.Quiet {
				fmt.Fprintf(dependencies.ErrorOutput, "More entries: rerun with --cursor %s\n", next)
			}
			return nil
		}
		if pages >= maximumListPages {
			_ = writer.Flush()
			return errs.New("listing_truncated", fmt.Sprintf("Stopped after %d pages; continue with --cursor %s.", pages, next), 1)
		}
		cursor = next
	}
	return writer.Flush()
}

// safeRelativeWorkspacePath mirrors the server's rule so an obviously bad
// path is refused locally and never sent.
func safeRelativeWorkspacePath(value string) bool {
	if value == "" {
		return true
	}
	if strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
