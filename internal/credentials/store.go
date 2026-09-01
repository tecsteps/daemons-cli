package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
)

// Credential is one Control Plane token bound to the normalized base URL it
// was issued for. Tokens for different hosts never share an entry.
type Credential struct {
	BaseURL      string `json:"-"`
	Token        string `json:"token"`
	AccountEmail string `json:"account_email,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

// Backend is the credential storage contract. The file store is the only
// implementation today; a keychain backend would satisfy the same interface.
// Load and Delete are keyed by the normalized Control Plane base URL so a
// login to a second host never overwrites the first.
type Backend interface {
	Load(baseURL string) (Credential, error)
	Save(credential Credential) error
	Delete(baseURL string) error
	Hosts() ([]string, error)
}

// Store is the owner-only JSON file backend.
type Store struct {
	Path string
}

var _ Backend = Store{}

// credentialFile is the on-disk document. Version 2 namespaces credentials
// by normalized base URL. Version 1 held a single credential with its
// base_url inline and is migrated transparently on the next Save.
type credentialFile struct {
	Version     int                   `json:"version"`
	Credentials map[string]Credential `json:"credentials,omitempty"`

	// Version 1 fields, read only for migration.
	BaseURL      string `json:"base_url,omitempty"`
	Token        string `json:"token,omitempty"`
	AccountEmail string `json:"account_email,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

func DefaultPath(environment map[string]string) (string, error) {
	if configured := environment["DAEMONS_CREDENTIALS_FILE"]; configured != "" {
		return configured, nil
	}

	if runtime.GOOS == "windows" {
		root := environment["LOCALAPPDATA"]
		if root == "" {
			return "", errors.New("LOCALAPPDATA is not set")
		}

		return filepath.Join(root, "daemons", "credentials.json"), nil
	}

	root := environment["XDG_CONFIG_HOME"]
	if root == "" {
		root = environment["HOME"]
		if root == "" {
			return "", errors.New("HOME is not set")
		}
		root = filepath.Join(root, ".config")
	}

	return filepath.Join(root, "daemons", "credentials.json"), nil
}

// Load returns the credential stored for baseURL, or fs.ErrNotExist when the
// file or that host's entry is absent.
func (s Store) Load(baseURL string) (Credential, error) {
	document, err := s.read()
	if err != nil {
		return Credential{}, err
	}
	credential, ok := document.Credentials[baseURL]
	if !ok {
		return Credential{}, fs.ErrNotExist
	}
	credential.BaseURL = baseURL
	return credential, nil
}

// Hosts lists the normalized base URLs with a stored credential, sorted.
func (s Store) Hosts() ([]string, error) {
	document, err := s.read()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	hosts := make([]string, 0, len(document.Credentials))
	for host := range document.Credentials {
		hosts = append(hosts, host)
	}
	sort.Strings(hosts)
	return hosts, nil
}

func (s Store) read() (credentialFile, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return credentialFile{}, fs.ErrNotExist
		}
		return credentialFile{}, fmt.Errorf("inspect credentials: %w", err)
	}
	if err := validateCredentialFile(s.Path, info); err != nil {
		return credentialFile{}, err
	}

	data, err := os.ReadFile(s.Path)
	if err != nil {
		return credentialFile{}, fmt.Errorf("read credentials: %w", err)
	}

	var document credentialFile
	if err := json.Unmarshal(data, &document); err != nil {
		return credentialFile{}, fmt.Errorf("decode credentials: %w", err)
	}
	switch document.Version {
	case 1:
		if document.BaseURL == "" || document.Token == "" {
			return credentialFile{}, errors.New("credentials file is invalid")
		}
		document.Credentials = map[string]Credential{document.BaseURL: {
			Token:        document.Token,
			AccountEmail: document.AccountEmail,
			ExpiresAt:    document.ExpiresAt,
		}}
	case 2:
		if document.Credentials == nil {
			document.Credentials = map[string]Credential{}
		}
		for host, credential := range document.Credentials {
			if host == "" || credential.Token == "" {
				return credentialFile{}, errors.New("credentials file is invalid")
			}
		}
	default:
		return credentialFile{}, errors.New("credentials file is invalid")
	}
	document.BaseURL, document.Token, document.AccountEmail, document.ExpiresAt = "", "", "", ""
	return document, nil
}

// Save stores the credential under its base URL, keeping every other host's
// entry. A version 1 file is rewritten as version 2 on the way through.
func (s Store) Save(credential Credential) error {
	if credential.BaseURL == "" || credential.Token == "" {
		return errors.New("base URL and token are required")
	}
	document, err := s.read()
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	if document.Credentials == nil {
		document.Credentials = map[string]Credential{}
	}
	baseURL := credential.BaseURL
	credential.BaseURL = ""
	document.Credentials[baseURL] = credential
	return s.write(document)
}

// Delete removes one host's credential. The file is removed once it holds
// no credentials at all. A missing entry is not an error.
func (s Store) Delete(baseURL string) error {
	document, err := s.read()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return err
	}
	delete(document.Credentials, baseURL)
	if len(document.Credentials) == 0 {
		return os.Remove(s.Path)
	}
	return s.write(document)
}

func (s Store) write(document credentialFile) error {
	document.Version = 2
	directory := filepath.Dir(s.Path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create credentials directory: %w", err)
	}
	directoryInfo, err := os.Lstat(directory)
	if err != nil {
		return fmt.Errorf("inspect credentials directory: %w", err)
	}
	if directoryInfo.Mode()&os.ModeSymlink != 0 || !directoryInfo.IsDir() {
		return errors.New("credentials directory must be a directory, not a symlink")
	}
	if err := validateOwner(directoryInfo); err != nil {
		return fmt.Errorf("credentials directory: %w", err)
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return fmt.Errorf("protect credentials directory: %w", err)
	}

	if info, err := os.Lstat(s.Path); err == nil {
		if err := validateCredentialFile(s.Path, info); err != nil {
			return err
		}
	} else if !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("inspect credentials: %w", err)
	}

	temporary, err := os.CreateTemp(directory, ".credentials-*")
	if err != nil {
		return fmt.Errorf("create temporary credentials: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return fmt.Errorf("protect temporary credentials: %w", err)
	}
	encoder := json.NewEncoder(temporary)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(document); err != nil {
		temporary.Close()
		return fmt.Errorf("encode credentials: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("sync credentials: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close credentials: %w", err)
	}
	if err := os.Rename(temporaryPath, s.Path); err != nil {
		return fmt.Errorf("replace credentials: %w", err)
	}

	return os.Chmod(s.Path, 0o600)
}

func validateCredentialFile(path string, info fs.FileInfo) error {
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return fmt.Errorf("credentials path %s must be a regular file, not a symlink", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("credentials file %s must have mode 0600", path)
	}
	if err := validateOwner(info); err != nil {
		return fmt.Errorf("credentials file %s: %w", path, err)
	}

	return nil
}
