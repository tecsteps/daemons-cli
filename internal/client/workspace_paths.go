package client

import (
	"path"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	// DefaultWorkspaceRoot is the confined guest workspace served by the access
	// relay (gateway/daemon/access-runtime-v1.mjs createAccessRelayHooks).
	DefaultWorkspaceRoot = "/home/dr-agent/workspace"
	// LegacyWorkspaceRoot is the unconfined root older guests still report in an
	// upload receipt path. It is accepted, never preferred.
	LegacyWorkspaceRoot = "/root/workspace"
	// DefaultUploadFolder is the workspace-relative folder upload writes into.
	DefaultUploadFolder = "uploads"
	// WorkspaceRootVariable overrides the accepted guest workspace root.
	WorkspaceRootVariable = "DAEMONS_WORKSPACE_ROOT"
	// UploadFolderVariable overrides the workspace-relative upload folder.
	UploadFolderVariable = "DAEMONS_UPLOAD_FOLDER"

	maximumWorkspaceRoot   = 4096
	maximumWorkspaceFolder = 1024
)

// WorkspacePaths carries the guest-side layout the CLI is willing to accept.
// Nothing here is sent to the Control Plane: it only decides which local input
// is safe to turn into a selector and which returned path may be printed.
type WorkspacePaths struct {
	roots  []string
	folder string
}

// DefaultWorkspacePaths prefers the confined root and still accepts the legacy
// one so an older guest's receipt path is not rejected as unsafe.
func DefaultWorkspacePaths() WorkspacePaths {
	return WorkspacePaths{roots: []string{DefaultWorkspaceRoot, LegacyWorkspaceRoot}, folder: DefaultUploadFolder}
}

// NewWorkspacePaths reads the optional overrides. An explicit root replaces the
// accepted set entirely, so a deployment cannot silently keep the legacy root.
func NewWorkspacePaths(environment map[string]string) (WorkspacePaths, error) {
	paths := DefaultWorkspacePaths()
	if configured := environment[WorkspaceRootVariable]; configured != "" {
		if !safeAbsoluteWorkspaceRoot(configured) {
			return WorkspacePaths{}, errs.New("unsafe_workspace_path", WorkspaceRootVariable+" must be a clean absolute path below / without . or .. segments.", 2)
		}
		paths.roots = []string{configured}
	}
	if configured, present := environment[UploadFolderVariable]; present {
		folder := strings.Trim(configured, "/")
		if folder != "" && !safeRelativeWorkspaceSegments(folder) {
			return WorkspacePaths{}, errs.New("unsafe_workspace_path", UploadFolderVariable+" must be a plain relative workspace folder without . or .. segments.", 2)
		}
		paths.folder = folder
	}
	return paths, nil
}

// Root is the workspace root the CLI prefers when it has to name one.
func (p WorkspacePaths) Root() string {
	if len(p.roots) == 0 {
		return DefaultWorkspaceRoot
	}
	return p.roots[0]
}

// Roots lists every accepted absolute root, preferred first.
func (p WorkspacePaths) Roots() []string {
	if len(p.roots) == 0 {
		return []string{DefaultWorkspaceRoot, LegacyWorkspaceRoot}
	}
	return append([]string(nil), p.roots...)
}

// UploadFolder is the workspace-relative folder, without a trailing separator.
func (p WorkspacePaths) UploadFolder() string { return p.folder }

// UploadSelector builds the single guest selector path for an upload. The
// server requires a basename, so a filename carrying a separator is refused
// locally and never sent.
func (p WorkspacePaths) UploadSelector(filename string) (string, error) {
	if filename == "" || filename == "." || filename == ".." || strings.ContainsAny(filename, "/\\\x00\r\n") {
		return "", errs.New("unsafe_workspace_path", "The upload filename is invalid.", 2)
	}
	selector := filename
	if p.folder != "" {
		selector = p.folder + "/" + filename
	}
	if len(selector) > maximumWorkspaceRoot {
		return "", errs.New("upload_limit", "The upload selector is too large.", 2)
	}
	return selector, nil
}

// Normalize accepts the relative API form and any accepted absolute root, and
// returns the relative workspace path the guest expects.
func (p WorkspacePaths) Normalize(value string) (string, error) {
	unsafe := func() (string, error) {
		return "", errs.New("unsafe_workspace_path", "PATH must be a plain relative workspace path without . or .. segments, or an absolute path below "+p.Root()+".", 2)
	}
	for _, root := range p.Roots() {
		switch {
		case value == root || value == root+"/":
			return "", nil
		case strings.HasPrefix(value, root+"/"):
			relative := strings.TrimSuffix(strings.TrimPrefix(value, root+"/"), "/")
			if relative != "" && !safeRelativeWorkspaceSegments(relative) {
				return unsafe()
			}
			return relative, nil
		}
	}
	if strings.HasPrefix(value, "/") {
		return unsafe()
	}
	relative := strings.TrimSuffix(value, "/")
	if relative != "" && !safeRelativeWorkspaceSegments(relative) {
		return unsafe()
	}
	return relative, nil
}

// SafeUploadPath checks a path the guest returned. It must be clean, absolute
// below an accepted root, and inside the configured upload folder.
func (p WorkspacePaths) SafeUploadPath(value string) bool {
	if value == "" || strings.ContainsAny(value, "\x00\r\n\\") || path.Clean(value) != value {
		return false
	}
	for _, root := range p.Roots() {
		prefix := root + "/"
		if p.folder != "" {
			prefix = root + "/" + p.folder + "/"
		}
		if strings.HasPrefix(value, prefix) && safeRelativeWorkspaceSegments(strings.TrimPrefix(value, prefix)) {
			return true
		}
	}
	return false
}

func safeAbsoluteWorkspaceRoot(value string) bool {
	if !strings.HasPrefix(value, "/") || value == "/" || len(value) > maximumWorkspaceRoot ||
		strings.ContainsAny(value, "\\\x00\r\n") || path.Clean(value) != value {
		return false
	}
	return safeRelativeWorkspaceSegments(strings.TrimPrefix(value, "/"))
}

func safeRelativeWorkspaceSegments(value string) bool {
	if value == "" || len(value) > maximumWorkspaceFolder || strings.ContainsAny(value, "\\\x00\r\n") {
		return false
	}
	for _, segment := range strings.Split(value, "/") {
		if segment == "" || segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
