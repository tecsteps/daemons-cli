package app

import (
	"context"
	"fmt"
	"os"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

func localPayloadCommand(upload bool) commandHandler {
	return func(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
		usage, count := "Usage: daemons payload receipt DAEMON OPERATION", 2
		if upload {
			usage, count = "Usage: daemons payload put DAEMON OPERATION FILE", 3
		}
		if helpRequested(arguments) {
			fmt.Fprintln(dependencies.Output, usage)
			return runResult{}
		}
		if len(arguments) != count || arguments[0] == "" || !uuidPattern.MatchString(arguments[1]) {
			return runResultFor(errs.New("usage_error", usage, 2))
		}
		var file *os.File
		if upload {
			stat, err := os.Lstat(arguments[2])
			if err != nil || !stat.Mode().IsRegular() || stat.Size() > 8*1024*1024 || stat.Size() == 0 {
				return runResultFor(errs.New("invalid_payload", "Use a nonempty regular E4 payload file no larger than 8 MiB.", 2))
			}
			file, err = os.Open(arguments[2])
			if err != nil {
				return runResultFor(errs.New("invalid_payload", "The local payload file could not be opened.", 2))
			}
			defer file.Close()
			opened, err := file.Stat()
			if err != nil || !os.SameFile(stat, opened) {
				return runResultFor(errs.New("invalid_payload", "The local payload file changed before opening.", 2))
			}
		}
		api, _, _, err := authenticatedClient(options, dependencies)
		if err != nil {
			return runResultFor(err)
		}
		daemonID, err := resolveDaemonID(ctx, api, arguments[0])
		if err != nil {
			return runResultFor(err)
		}
		var receipt client.LocalPayloadReceipt
		if upload {
			receipt, err = api.PutLocalPayload(ctx, daemonID, arguments[1], file)
		} else {
			receipt, err = api.GetLocalPayloadReceipt(ctx, daemonID, arguments[1])
		}
		if err != nil {
			return runResultFor(err)
		}
		if options.JSON {
			writeJSON(dependencies.Output, map[string]any{"data": receipt, "meta": map[string]any{}})
		} else {
			fmt.Fprintf(dependencies.Output, "Payload %s: %s (revision %d)\n", receipt.PayloadID, receipt.Phase, receipt.Revision)
		}
		if receipt.Phase == "rejected" || receipt.Phase == "needs_reconcile" {
			return runResult{code: 1, err: errs.New("payload_"+receipt.Phase, "The guest has not applied this payload.", 1), reported: options.JSON}
		}
		return runResult{}
	}
}
