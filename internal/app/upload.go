package app

import (
	"context"
	"fmt"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/upload"
)

const uploadUsage = "Usage: daemons upload DAEMON PATH... [--force]"

func uploadFiles(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, uploadUsage)
		return runResult{}
	}
	operands := make([]string, 0, len(arguments))
	force := false
	for _, argument := range arguments {
		if argument == "--force" {
			force = true
			continue
		}
		operands = append(operands, argument)
	}
	if len(operands) < 2 {
		err := errs.New("usage_error", uploadUsage, 2)
		return reportUploadFailure(options, dependencies, max(0, len(operands)-1), err)
	}
	paths, err := workspacePaths(dependencies)
	if err != nil {
		return reportUploadFailure(options, dependencies, len(operands)-1, err)
	}
	files, err := upload.Validate(operands[1:], dependencies.Environment["HOME"])
	if err != nil {
		return reportUploadFailure(options, dependencies, len(operands)-1, err)
	}
	defer upload.Close(files)
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return reportUploadFailure(options, dependencies, len(files), err)
	}
	daemon, err := api.ResolveDaemon(ctx, operands[0])
	if err != nil {
		return reportUploadFailure(options, dependencies, len(files), err)
	}
	if daemon.Status != "running" {
		err := errs.New("daemon_not_running", "The daemon is not running. Start it before uploading.", 1)
		return reportUploadFailure(options, dependencies, len(files), err)
	}
	staging, err := uploadStaging(options, dependencies, daemon.ID)
	if err != nil {
		return reportUploadFailure(options, dependencies, len(files), err)
	}

	report, runErr := upload.Run(ctx, api, daemon.ID, files, upload.Options{
		Paths:   paths,
		Staging: &staging,
		Now:     dependencies.Now,
		Force:   force,
	})
	if options.JSON {
		writeJSON(dependencies.Output, report)
		return runResult{code: errs.ExitCode(runErr), err: runErr, reported: true}
	}
	for _, result := range report.Data.Results {
		if result.Status == "uploaded" {
			fmt.Fprintln(dependencies.Output, result.Path)
		}
	}
	return runResultFor(runErr)
}

// uploadStaging resolves the private record that keeps an interrupted upload's
// identity recoverable without holding any file bytes.
func uploadStaging(options globalOptions, dependencies Dependencies, daemonID string) (upload.Staging, error) {
	return upload.OpenStaging(dependencies.Environment, options.CredentialsFile, daemonID)
}

func reportUploadFailure(options globalOptions, dependencies Dependencies, requested int, err error) runResult {
	if !options.JSON {
		return runResultFor(err)
	}
	writeJSON(dependencies.Output, emptyUploadReport(requested, err))
	return runResult{code: errs.ExitCode(err), err: err, reported: true}
}

func emptyUploadReport(requested int, err error) upload.Report {
	report := upload.Report{}
	report.Meta.Requested = requested
	report.Data.Results = make([]upload.Result, requested)
	for index := range report.Data.Results {
		report.Data.Results[index] = upload.Result{Index: index, Status: "not_attempted"}
	}
	report.Error = &upload.Problem{Code: errs.Code(err), Message: sanitizeText(err.Error()), FailedIndex: 0}
	return report
}
