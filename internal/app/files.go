package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	filesListUsage = "Usage: daemons files list DAEMON [PATH] [--cursor CURSOR] [--limit N] [--all]"
	// maximumListPages bounds --all so a listing can never turn into an
	// unbounded crawl of a large workspace.
	maximumListPages = 50
)

// listFiles reads a workspace directory inventory without fetching file content.
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
	paths, err := workspacePaths(dependencies)
	if err != nil {
		return err
	}
	workspacePath := ""
	if len(positionals) == 2 {
		var pathErr error
		workspacePath, pathErr = normalizeWorkspacePath(paths, positionals[1])
		if pathErr != nil {
			return pathErr
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
	api = withWorkingProof(api, daemonID, options, dependencies)

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	if err := api.Preflight(ctx); err != nil {
		return err
	}
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
				fmt.Fprintf(writer, "%s\t%d\t%s\t%s\n", entry.Type, entry.Size, time.Unix(int64(entry.MTime), 0).UTC().Format(time.RFC3339), sanitizeText(entry.Name))
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

// workspacePaths reads the configurable guest layout once per command. The
// confined root is the default; DAEMONS_WORKSPACE_ROOT replaces it.
func workspacePaths(dependencies Dependencies) (client.WorkspacePaths, error) {
	return client.NewWorkspacePaths(dependencies.Environment)
}

// normalizeWorkspacePath accepts the relative API form and the absolute path
// returned by upload. Other absolute paths remain local validation errors.
func normalizeWorkspacePath(paths client.WorkspacePaths, value string) (string, error) {
	return paths.Normalize(value)
}

func downloadFile(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	const usage = "Usage: daemons files download DAEMON PATH DESTINATION"
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, usage)
		return nil
	}
	if len(arguments) != 3 || arguments[0] == "" || arguments[2] == "" || arguments[2] == "-" {
		return errs.New("usage_error", usage, 2)
	}
	paths, err := workspacePaths(dependencies)
	if err != nil {
		return err
	}
	workspacePath, err := normalizeWorkspacePath(paths, arguments[1])
	if err != nil {
		return err
	}
	if workspacePath == "" {
		return errs.New("usage_error", "PATH must name a workspace file.", 2)
	}
	destination := arguments[2]
	if _, err := os.Lstat(destination); !os.IsNotExist(err) {
		return errs.New("download_destination", "The destination must be a new file in an existing directory.", 2)
	}
	temporary, err := os.CreateTemp(filepath.Dir(destination), ".daemons-download-*")
	if err != nil {
		return errs.New("download_destination", "Cannot create a private download file in the destination directory.", 2)
	}
	defer os.Remove(temporary.Name())
	defer temporary.Close()
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	daemonID, err := resolveDaemonID(ctx, api, arguments[0])
	if err != nil {
		return err
	}
	api = withWorkingProof(api, daemonID, options, dependencies)
	if err := api.DownloadFile(ctx, daemonID, workspacePath, temporary); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return errs.New("download_destination", "The downloaded file could not be saved.", 8)
	}
	if err := temporary.Close(); err != nil {
		return errs.New("download_destination", "The downloaded file could not be saved.", 8)
	}
	// A hard link publishes the complete file atomically without replacing a concurrent writer.
	if err := os.Link(temporary.Name(), destination); err != nil {
		return errs.New("download_destination", "The destination could not be created. Existing files were preserved.", 8)
	}
	if options.JSON {
		writeJSON(dependencies.Output, map[string]any{"data": map[string]string{"path": destination}, "meta": map[string]any{}})
	} else if !options.Quiet {
		fmt.Fprintln(dependencies.Output, sanitizeText(destination))
	}
	return nil
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
