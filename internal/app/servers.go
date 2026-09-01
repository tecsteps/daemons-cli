package app

import (
	"context"
	"fmt"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func listServers(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons servers list")
		return nil
	}
	if len(arguments) != 0 {
		return errs.New("usage_error", "Usage: daemons servers list", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.ListServers(ctx)
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}

	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "NAME\tSTATUS\tREGION\tCORES\tMEMORY\tDISK\tDAEMONS")
	for _, server := range result.Data {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%d\t%d GB\t%d GB\t%d\n", server.Name, server.Status, server.Region, server.Capacity.Cores, server.Capacity.MemoryGB, server.Capacity.DiskGB, server.Capacity.DaemonCount)
	}
	return writer.Flush()
}

func showServer(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, "Usage: daemons servers show ID")
		return nil
	}
	if len(arguments) != 1 {
		return errs.New("usage_error", "Usage: daemons servers show ID", 2)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	result, err := api.ShowServer(ctx, arguments[0])
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}
	server := result.Data
	fmt.Fprintf(dependencies.Output, "ID: %s\nName: %s\nStatus: %s\nRegion: %s\nCores: %d\nMemory: %d GB\nDisk: %d GB\nDaemons: %d\n", server.ID, server.Name, server.Status, server.Region, server.Capacity.Cores, server.Capacity.MemoryGB, server.Capacity.DiskGB, server.Capacity.DaemonCount)
	return nil
}
