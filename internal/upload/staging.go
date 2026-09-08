package upload

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/tecsteps/daemons-cli/internal/credentials"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

// Pending records one upload the CLI has started but not yet seen resolved.
// It carries identity and intent only: no file bytes are ever staged locally,
// so recovery resolves a receipt and never replays a mutation.
type Pending struct {
	OperationUUID string `json:"operation_uuid"`
	Selector      string `json:"selector"`
	Filename      string `json:"filename"`
	Bytes         int64  `json:"bytes"`
	StartedAt     string `json:"started_at"`
}

type stagingFile struct {
	Version int       `json:"version"`
	Pending []Pending `json:"pending"`
}

// Staging is the per-daemon local record of in-flight upload operations.
type Staging struct {
	path string
}

var (
	stagingID   = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$`)
	operationID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
)

const maximumPending = 256

// OpenStaging resolves the private staging record beside the credential file.
// The daemon identifier becomes one path segment, so it is validated first.
func OpenStaging(environment map[string]string, credentialsFile, daemonID string) (Staging, error) {
	if !stagingID.MatchString(daemonID) {
		return Staging{}, errs.New("usage_error", "The daemon identifier cannot name an upload staging record.", 2)
	}
	if credentialsFile == "" {
		resolved, err := credentials.DefaultPath(environment)
		if err != nil {
			return Staging{}, errs.New("upload_staging_unavailable", "Could not determine where to record pending uploads.", 1)
		}
		credentialsFile = resolved
	}
	return Staging{path: filepath.Join(filepath.Dir(credentialsFile), "uploads", daemonID+".json")}, nil
}

// Path is the staging record location, for diagnostics and tests.
func (s Staging) Path() string { return s.path }

// List returns the pending operations, oldest first. A missing record is empty.
func (s Staging) List() ([]Pending, error) {
	raw, err := os.ReadFile(s.path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, errs.New("upload_staging_unreadable", "The pending upload record could not be read.", 1)
	}
	var document stagingFile
	if json.Unmarshal(raw, &document) != nil || document.Version != 1 {
		return nil, errs.New("upload_staging_unreadable", "The pending upload record is not readable; remove "+s.path+" after checking each operation with daemons files receipt.", 1)
	}
	kept := make([]Pending, 0, len(document.Pending))
	for _, entry := range document.Pending {
		if operationID.MatchString(entry.OperationUUID) {
			kept = append(kept, entry)
		}
	}
	return kept, nil
}

// Add records an operation before its request leaves the CLI.
func (s Staging) Add(entry Pending, now time.Time) error {
	if !operationID.MatchString(entry.OperationUUID) {
		return errs.New("usage_error", "A pending upload needs an operation UUID.", 2)
	}
	entry.StartedAt = now.UTC().Format(time.RFC3339)
	current, err := s.List()
	if err != nil {
		return err
	}
	if len(current) >= maximumPending {
		return errs.New("upload_staging_full", "Too many unresolved uploads are recorded. Run daemons files recover DAEMON first.", 1)
	}
	return s.write(append(current, entry))
}

// Remove clears one resolved operation. Recovery and a confirmed upload both
// use it; nothing else may delete a record that is still unresolved.
func (s Staging) Remove(operationUUID string) error {
	current, err := s.List()
	if err != nil {
		return err
	}
	kept := make([]Pending, 0, len(current))
	for _, entry := range current {
		if entry.OperationUUID != operationUUID {
			kept = append(kept, entry)
		}
	}
	if len(kept) == len(current) {
		return nil
	}
	return s.write(kept)
}

func (s Staging) write(entries []Pending) error {
	if len(entries) == 0 {
		if err := os.Remove(s.path); err != nil && !errors.Is(err, fs.ErrNotExist) {
			return errs.New("upload_staging_unwritable", "The pending upload record could not be cleared.", 1)
		}
		return nil
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return errs.New("upload_staging_unwritable", "The pending upload directory could not be created.", 1)
	}
	raw, err := json.Marshal(stagingFile{Version: 1, Pending: entries})
	if err != nil {
		return errs.New("upload_staging_unwritable", "The pending upload record could not be encoded.", 1)
	}
	temporary, err := os.CreateTemp(directory, ".uploads-*")
	if err != nil {
		return errs.New("upload_staging_unwritable", "The pending upload record could not be written.", 1)
	}
	defer os.Remove(temporary.Name())
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return errs.New("upload_staging_unwritable", "The pending upload record could not be protected.", 1)
	}
	if _, err := temporary.Write(raw); err != nil {
		temporary.Close()
		return errs.New("upload_staging_unwritable", "The pending upload record could not be written.", 1)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return errs.New("upload_staging_unwritable", "The pending upload record could not be written.", 1)
	}
	if err := temporary.Close(); err != nil {
		return errs.New("upload_staging_unwritable", "The pending upload record could not be written.", 1)
	}
	if err := os.Rename(temporary.Name(), s.path); err != nil {
		return errs.New("upload_staging_unwritable", "The pending upload record could not be published.", 1)
	}
	return nil
}
