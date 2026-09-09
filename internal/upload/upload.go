package upload

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	MaxFiles    = 10
	MaxFileSize = 10 * 1024 * 1024
	// maximumCollisionPages bounds the pre-upload collision listing so a large
	// upload folder can never turn one upload into an unbounded crawl.
	maximumCollisionPages = 20
)

// Options carries the configurable guest layout, the local staging record and
// the explicit overwrite consent for one upload run.
type Options struct {
	Paths   client.WorkspacePaths
	Staging *Staging
	Now     func() time.Time
	Force   bool
}

func (o Options) paths() client.WorkspacePaths {
	if len(o.Paths.Roots()) == 0 {
		return client.DefaultWorkspacePaths()
	}
	return o.Paths
}

func (o Options) now() time.Time {
	if o.Now == nil {
		return time.Now()
	}
	return o.Now()
}

type OpenFile struct {
	Index    int
	Path     string
	Filename string
	File     *os.File
}

type Result struct {
	Index  int    `json:"index"`
	Status string `json:"status"`
	Path   string `json:"path,omitempty"`
}

type Problem struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	FailedIndex int    `json:"failed_index"`
	// Operation names the upload identity to resolve with daemons files recover
	// or daemons files receipt. It is empty when no request was sent.
	Operation string `json:"operation,omitempty"`
}

type Report struct {
	Data struct {
		Results []Result `json:"results"`
	} `json:"data"`
	Error *Problem `json:"error"`
	Meta  struct {
		Uploaded  int `json:"uploaded"`
		Requested int `json:"requested"`
	} `json:"meta"`
}

func Validate(operands []string, home string) ([]OpenFile, error) {
	if len(operands) < 1 || len(operands) > MaxFiles {
		return nil, errs.New("usage_error", "Upload requires between 1 and 10 local file paths.", 2)
	}

	opened := make([]OpenFile, 0, len(operands))
	closeOpened := func() {
		for _, candidate := range opened {
			candidate.File.Close()
		}
	}

	for index, operand := range operands {
		resolved, err := resolvePath(operand, home)
		if err != nil {
			closeOpened()
			return nil, errs.New("local_file_invalid", err.Error(), 1)
		}
		file, err := os.Open(resolved)
		if err != nil {
			closeOpened()
			return nil, errs.New("local_file_unreadable", fmt.Sprintf("Cannot read local file %s.", operand), 1)
		}
		info, err := file.Stat()
		if err != nil || !info.Mode().IsRegular() {
			file.Close()
			closeOpened()
			return nil, errs.New("local_file_not_regular", fmt.Sprintf("Local path %s is not a regular file.", operand), 1)
		}
		if info.Size() > MaxFileSize {
			file.Close()
			closeOpened()
			return nil, errs.New("file_too_large", fmt.Sprintf("Local file %s is larger than 10 MB.", operand), 7)
		}

		opened = append(opened, OpenFile{
			Index:    index,
			Path:     resolved,
			Filename: filepath.Base(resolved),
			File:     file,
		})
	}

	return opened, nil
}

func Close(files []OpenFile) {
	for _, file := range files {
		file.File.Close()
	}
}

func Run(ctx context.Context, api *client.Client, daemonID string, files []OpenFile, options Options) (Report, error) {
	report := Report{}
	report.Meta.Requested = len(files)
	report.Data.Results = make([]Result, len(files))
	for index := range report.Data.Results {
		report.Data.Results[index] = Result{Index: index, Status: "not_attempted"}
	}
	paths := options.paths()
	staging := options.Staging
	if staging != nil {
		recoverable, err := api.UploadRecoverable(ctx)
		if err != nil {
			report.Error = &Problem{Code: errs.Code(err), Message: errs.Redact(err.Error()), FailedIndex: 0}
			return report, err
		}
		if !recoverable {
			staging = nil
		}
	}

	if !options.Force {
		if err := assertNoOverwrite(ctx, api, daemonID, files, paths); err != nil {
			report.Error = &Problem{Code: errs.Code(err), Message: errs.Redact(err.Error()), FailedIndex: 0}
			return report, err
		}
	}

	for _, local := range files {
		operation := client.NewUploadOperationID()
		selector, err := paths.UploadSelector(local.Filename)
		if err == nil && staging != nil {
			size := int64(0)
			if info, statErr := local.File.Stat(); statErr == nil {
				size = info.Size()
			}
			err = staging.Add(Pending{OperationUUID: operation, Selector: selector,
				Filename: local.Filename, Bytes: size}, options.now())
		}
		var response client.UploadResponse
		if err == nil {
			response, err = api.UploadOperation(ctx, daemonID, operation, paths, local.Filename, local.File)
		}
		if err != nil {
			status := "not_attempted"
			if errs.ExitCode(err) == 8 {
				status = "unknown"
			} else if staging != nil {
				// A definite refusal leaves nothing to recover.
				_ = staging.Remove(operation)
			}
			report.Data.Results[local.Index].Status = status
			report.Error = &Problem{
				Code:        errs.Code(err),
				Message:     errs.Redact(err.Error()),
				FailedIndex: local.Index,
				Operation:   operation,
			}
			return report, err
		}
		if !response.OK || !paths.SafeUploadPath(response.Path) {
			err := errs.New("unsafe_server_path", "The server returned an unsafe upload path.", 10)
			report.Error = &Problem{Code: errs.Code(err), Message: errs.Redact(err.Error()), FailedIndex: local.Index, Operation: operation}
			return report, err
		}
		if staging != nil {
			_ = staging.Remove(operation)
		}

		report.Data.Results[local.Index] = Result{Index: local.Index, Status: "uploaded", Path: response.Path}
		report.Meta.Uploaded++
	}

	return report, nil
}

// assertNoOverwrite refuses silently replacing a workspace file. The listing is
// a read; the upload itself is never attempted when consent is missing.
func assertNoOverwrite(ctx context.Context, api *client.Client, daemonID string, files []OpenFile, paths client.WorkspacePaths) error {
	wanted := make(map[string]bool, len(files))
	for _, local := range files {
		wanted[local.Filename] = true
	}
	cursor := ""
	for page := 0; page < maximumCollisionPages; page++ {
		listing, err := api.ListFiles(ctx, daemonID, paths.UploadFolder(), cursor, 200)
		if err != nil {
			if errs.ExitCode(err) == 4 {
				// The upload folder does not exist yet, so nothing collides.
				return nil
			}
			return err
		}
		for _, entry := range listing.Data {
			if wanted[entry.Name] {
				return errs.New("upload_overwrite_confirmation",
					"Uploading would replace an existing workspace file. Rerun with --force to overwrite.", 6)
			}
		}
		if listing.Meta.NextCursor == nil || *listing.Meta.NextCursor == "" {
			return nil
		}
		cursor = *listing.Meta.NextCursor
	}
	return errs.New("upload_overwrite_confirmation",
		"The upload folder is too large to check for collisions. Rerun with --force to overwrite.", 6)
}

func resolvePath(operand, home string) (string, error) {
	if operand == "" {
		return "", errors.New("Local file path cannot be empty.")
	}
	if operand == "~" {
		if home == "" {
			return "", errors.New("Cannot expand ~ because the home directory is unavailable.")
		}
		operand = home
	} else if strings.HasPrefix(operand, "~/") {
		if home == "" {
			return "", errors.New("Cannot expand ~ because the home directory is unavailable.")
		}
		operand = filepath.Join(home, strings.TrimPrefix(operand, "~/"))
	}
	absolute, err := filepath.Abs(operand)
	if err != nil {
		return "", fmt.Errorf("Cannot resolve local file %s.", operand)
	}
	return filepath.Clean(absolute), nil
}

func IsMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
