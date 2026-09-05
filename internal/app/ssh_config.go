package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

// sshConfig writes a separately included, entirely managed file. Values from
// the API are constrained before they enter OpenSSH syntax.
func sshConfig(ctx context.Context, args []string, opt globalOptions, d Dependencies) error {
	if helpRequested(args) {
		fmt.Fprintln(d.Output, "Usage: daemons ssh-config DAEMON [--identity PATH] [--remove]")
		return nil
	}
	filtered := make([]string, 0, len(args))
	removeFlag := false
	for _, a := range args {
		if a == "--remove" {
			removeFlag = true
			continue
		}
		filtered = append(filtered, a)
	}
	args = filtered
	f, e := parseMutationFlags(args, []string{"--identity"}, "Usage: daemons ssh-config DAEMON [--identity PATH] [--remove] [--json]", opt, d)
	if e != nil {
		return e
	}
	remove := removeFlag
	if len(f.Positionals) != 1 {
		return errs.New("usage_error", "Usage: daemons ssh-config DAEMON [--identity PATH] [--remove]", 2)
	}
	api, base, _, e := authenticatedClient(opt, d)
	if e != nil {
		return e
	}
	root, e := sshRoot(base, d.Environment)
	if e != nil {
		return e
	}
	if remove {
		return removeSSHConfig(filepath.Join(root, originHash(base)), f.Positionals[0])
	}
	access, e := api.SSH(ctx, f.Positionals[0])
	if e != nil {
		return e
	}
	if !access.Data.Enabled || !access.Data.Reconciled {
		return errs.New("ssh_not_ready", "SSH is not enabled and reconciled for this daemon.", 1)
	}
	if unsafeSSH(access.Data.HostKey) || unsafeSSH(access.Data.HostKeyFingerprint) {
		return errs.New("invalid_response", "The SSH export contains unsafe fields.", 1)
	}
	identity := f.Values["--identity"]
	if identity == "" {
		identity = filepath.Join(d.Environment["HOME"], ".ssh", "id_ed25519")
	}
	if strings.ContainsAny(identity, "\r\n") {
		return errs.New("usage_error", "Identity paths cannot contain newlines.", 2)
	}
	hash := originHash(base)
	alias := "dr-" + hash + "-" + f.Positionals[0]
	managed := filepath.Join(root, hash)
	if e = secureDir(managed); e != nil {
		return e
	}
	known := filepath.Join(managed, "known_hosts")
	config := filepath.Join(managed, "config")
	mapPath := filepath.Join(managed, "aliases.json")
	stanza := fmt.Sprintf("# daemons-run daemon %s\nHost %s\n    HostName ignored\n    User root\n    ProxyCommand %s ssh-proxy %s\n    IdentityFile %s\n    IdentitiesOnly yes\n    HostKeyAlias %s\n    UserKnownHostsFile %s\n    StrictHostKeyChecking yes\n    ForwardAgent no\n    ForwardX11 no\n", f.Positionals[0], alias, sshQuote(executablePath()), f.Positionals[0], sshQuote(identity), "dr-"+f.Positionals[0], sshQuote(known))
	prior, _ := os.ReadFile(config)
	if e = atomicPrivate(config, replaceManagedStanza(string(prior), f.Positionals[0], stanza)); e != nil {
		return e
	}
	oldKnown, _ := os.ReadFile(known)
	lines := []string{}
	for _, line := range strings.Split(string(oldKnown), "\n") {
		if line != "" && !strings.HasPrefix(line, "dr-"+f.Positionals[0]+" ") {
			lines = append(lines, line)
		}
	}
	if e = atomicPrivate(known, []byte(strings.Join(lines, "\n")+"\n"+"dr-"+f.Positionals[0]+" "+access.Data.HostKey+"\n")); e != nil {
		return e
	}
	m := map[string]string{}
	if priorMap, readErr := os.ReadFile(mapPath); readErr == nil { _ = json.Unmarshal(priorMap, &m) }
	m[f.Positionals[0]] = alias
	b, _ := json.Marshal(m)
	if e = atomicPrivate(mapPath, b); e != nil {
		return e
	}
	if e = ensureInclude(root, config); e != nil {
		return e
	}
	if opt.JSON {
		writeCanonicalJSON(d.Output, access.Raw)
	} else {
		fmt.Fprintln(d.Output, alias)
	}
	return nil
}
func replaceManagedStanza(old, daemon, stanza string) []byte {
	marker := "# daemons-run daemon " + daemon + "\n"
	start := strings.Index(old, marker)
	if start < 0 {
		return []byte(old + stanza)
	}
	end := strings.Index(old[start+len(marker):], "# daemons-run daemon ")
	if end < 0 {
		return []byte(old[:start] + stanza)
	}
	return []byte(old[:start] + stanza + old[start+len(marker)+end:])
}
func sshRoot(_ string, env map[string]string) (string, error) {
	h := env["HOME"]
	if h == "" {
		return "", errors.New("HOME is not set")
	}
	return filepath.Join(h, ".ssh", "daemons-run"), nil
}
func originHash(v string) string { s := sha256.Sum256([]byte(v)); return hex.EncodeToString(s[:])[:16] }
func unsafeSSH(v string) bool    { return v == "" || strings.ContainsAny(v, "\r\n\x00") }
func sshQuote(v string) string   { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
func executablePath() string {
	p, e := os.Executable()
	if e != nil || !filepath.IsAbs(p) {
		return "daemons"
	}
	return p
}
func secureDir(p string) error {
	if e := os.MkdirAll(p, 0700); e != nil {
		return e
	}
	i, e := os.Lstat(p)
	if e != nil {
		return e
	}
	if i.Mode()&os.ModeSymlink != 0 || !i.IsDir() {
		return errors.New("managed SSH directory is unsafe")
	}
	return os.Chmod(p, 0700)
}
func atomicPrivate(path string, b []byte) error {
	if i, e := os.Lstat(path); e == nil && i.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing SSH symlink target")
	}
	dir := filepath.Dir(path)
	tmp, e := os.CreateTemp(dir, ".daemons-")
	if e != nil {
		return e
	}
	name := tmp.Name()
	defer os.Remove(name)
	if e = tmp.Chmod(0600); e == nil {
		_, e = tmp.Write(b)
	}
	if c := tmp.Close(); e == nil {
		e = c
	}
	if e != nil {
		return e
	}
	return os.Rename(name, path)
}
func ensureInclude(root, config string) error {
	ssh := filepath.Dir(root)
	if e := secureDir(ssh); e != nil {
		return e
	}
	path := filepath.Join(ssh, "config")
	if i, e := os.Lstat(path); e == nil && i.Mode()&os.ModeSymlink != 0 {
		return errors.New("refusing SSH config symlink")
	}
	old, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return err
	}
	line := "# daemons-run managed include\nInclude " + sshQuote(config) + "\n"
	if strings.Contains(string(old), "# daemons-run managed include\n") {
		return nil
	}
	if errors.Is(err, fs.ErrNotExist) || len(old) == 0 {
		return atomicPrivate(path, []byte(line))
	}
	if _, e := os.Stat(path + ".daemons-run.bak"); errors.Is(e, fs.ErrNotExist) {
		if e = atomicPrivate(path+".daemons-run.bak", old); e != nil {
			return e
		}
	}
	return atomicPrivate(path, append([]byte(line), old...))
}
func removeSSHConfig(root, daemon string) error {
	for _, name := range []string{"config", "known_hosts", "aliases.json"} {
		p := filepath.Join(root, name)
		if i, e := os.Lstat(p); e == nil {
			if i.Mode()&os.ModeSymlink != 0 {
				return errors.New("refusing SSH symlink target")
			}
			if e := os.Remove(p); e != nil {
				return e
			}
		}
	}
	// Remove only our two-line Include, preserving every user stanza.
	sshConfig := filepath.Join(filepath.Dir(filepath.Dir(root)), "config")
	if i, e := os.Lstat(sshConfig); e == nil {
		if i.Mode()&os.ModeSymlink != 0 {
			return errors.New("refusing SSH config symlink")
		}
		b, e := os.ReadFile(sshConfig)
		if e != nil {
			return e
		}
		line := "# daemons-run managed include\nInclude " + sshQuote(filepath.Join(root, "config")) + "\n"
		if strings.Contains(string(b), line) {
			if e := atomicPrivate(sshConfig, []byte(strings.Replace(string(b), line, "", 1))); e != nil {
				return e
			}
		}
	}
	_ = daemon
	return nil
}
