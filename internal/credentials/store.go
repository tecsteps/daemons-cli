package credentials

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
)

type Credential struct {
	Version      int    `json:"version"`
	BaseURL      string `json:"base_url"`
	Token        string `json:"token"`
	AccountEmail string `json:"account_email,omitempty"`
	ExpiresAt    string `json:"expires_at,omitempty"`
}

type Store struct {
	Path string
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

func (s Store) Load() (Credential, error) {
	info, err := os.Lstat(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return Credential{}, fs.ErrNotExist
		}
		return Credential{}, fmt.Errorf("inspect credentials: %w", err)
	}
	if err := validateCredentialFile(s.Path, info); err != nil {
		return Credential{}, err
	}

	data, err := os.ReadFile(s.Path)
	if err != nil {
		return Credential{}, fmt.Errorf("read credentials: %w", err)
	}

	var credential Credential
	if err := json.Unmarshal(data, &credential); err != nil {
		return Credential{}, fmt.Errorf("decode credentials: %w", err)
	}
	if credential.Version != 1 || credential.BaseURL == "" || credential.Token == "" {
		return Credential{}, errors.New("credentials file is invalid")
	}

	return credential, nil
}

func (s Store) Save(credential Credential) error {
	credential.Version = 1
	if credential.BaseURL == "" || credential.Token == "" {
		return errors.New("base URL and token are required")
	}

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
	if err := encoder.Encode(credential); err != nil {
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

func (s Store) Delete() error {
	info, err := os.Lstat(s.Path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("inspect credentials: %w", err)
	}
	if err := validateCredentialFile(s.Path, info); err != nil {
		return err
	}

	return os.Remove(s.Path)
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
