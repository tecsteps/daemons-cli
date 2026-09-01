package upload

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	MaxFiles    = 10
	MaxFileSize = 10 * 1024 * 1024
	uploadRoot  = "/root/workspace/uploads"
)

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

func Run(ctx context.Context, api *client.Client, daemonID string, files []OpenFile) (Report, error) {
	report := Report{}
	report.Meta.Requested = len(files)
	report.Data.Results = make([]Result, len(files))
	for index := range report.Data.Results {
		report.Data.Results[index] = Result{Index: index, Status: "not_attempted"}
	}

	for _, local := range files {
		response, err := api.Upload(ctx, daemonID, local.Filename, local.File)
		if err != nil {
			status := "not_attempted"
			if errs.ExitCode(err) == 8 {
				status = "unknown"
			}
			report.Data.Results[local.Index].Status = status
			report.Error = &Problem{
				Code:        errs.Code(err),
				Message:     errs.Redact(err.Error()),
				FailedIndex: local.Index,
			}
			return report, err
		}
		if !response.OK || !safeUploadPath(response.Path) {
			err := errs.New("unsafe_server_path", "The server returned an unsafe upload path.", 10)
			report.Error = &Problem{Code: errs.Code(err), Message: errs.Redact(err.Error()), FailedIndex: local.Index}
			return report, err
		}

		report.Data.Results[local.Index] = Result{Index: local.Index, Status: "uploaded", Path: response.Path}
		report.Meta.Uploaded++
	}

	return report, nil
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

func safeUploadPath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	cleaned := path.Clean(value)
	return cleaned == value && strings.HasPrefix(cleaned, uploadRoot+"/") && path.Base(cleaned) != "."
}

func IsMissing(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
