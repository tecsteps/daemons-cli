package client

import (
	"testing"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

func TestWorkspacePathsDefaultToTheConfinedRoot(t *testing.T) {
	paths := DefaultWorkspacePaths()
	if paths.Root() != "/home/dr-agent/workspace" {
		t.Fatalf("Root() = %q", paths.Root())
	}
	if paths.UploadFolder() != "uploads" {
		t.Fatalf("UploadFolder() = %q", paths.UploadFolder())
	}
	selector, err := paths.UploadSelector("note.txt")
	if err != nil || selector != "uploads/note.txt" {
		t.Fatalf("UploadSelector() = %q, %v", selector, err)
	}
	// The legacy root stays acceptable so an older guest receipt still parses.
	for _, accepted := range []string{"/home/dr-agent/workspace/uploads/a", "/root/workspace/uploads/a"} {
		if !paths.SafeUploadPath(accepted) {
			t.Fatalf("SafeUploadPath(%q) = false", accepted)
		}
	}
}

func TestWorkspacePathsHonourEnvironmentOverrides(t *testing.T) {
	paths, err := NewWorkspacePaths(map[string]string{
		WorkspaceRootVariable: "/srv/workspace",
		UploadFolderVariable:  "inbox/staged",
	})
	if err != nil {
		t.Fatal(err)
	}
	if paths.Root() != "/srv/workspace" || len(paths.Roots()) != 1 {
		t.Fatalf("roots = %v", paths.Roots())
	}
	selector, err := paths.UploadSelector("note.txt")
	if err != nil || selector != "inbox/staged/note.txt" {
		t.Fatalf("UploadSelector() = %q, %v", selector, err)
	}
	if !paths.SafeUploadPath("/srv/workspace/inbox/staged/note.txt") {
		t.Fatal("configured upload path rejected")
	}
	// An explicit root replaces the accepted set; the defaults no longer apply.
	if paths.SafeUploadPath("/root/workspace/uploads/note.txt") {
		t.Fatal("legacy root survived an explicit override")
	}
	relative, err := paths.Normalize("/srv/workspace/src/main.go")
	if err != nil || relative != "src/main.go" {
		t.Fatalf("Normalize() = %q, %v", relative, err)
	}
	if _, err := paths.Normalize("/etc/passwd"); errs.ExitCode(err) != 2 {
		t.Fatalf("Normalize(/etc/passwd) = %v", err)
	}
}

func TestWorkspacePathsRefuseUnsafeConfiguration(t *testing.T) {
	for _, environment := range []map[string]string{
		{WorkspaceRootVariable: "relative/root"},
		{WorkspaceRootVariable: "/"},
		{WorkspaceRootVariable: "/srv/../etc"},
		{WorkspaceRootVariable: "/srv/work\nspace"},
		{UploadFolderVariable: "../escape"},
		{UploadFolderVariable: "a/../../b"},
	} {
		if _, err := NewWorkspacePaths(environment); errs.ExitCode(err) != 2 {
			t.Fatalf("NewWorkspacePaths(%v) accepted the value: %v", environment, err)
		}
	}
}

func TestUploadSelectorRequiresABasename(t *testing.T) {
	paths := DefaultWorkspacePaths()
	for _, filename := range []string{"", ".", "..", "a/b", "a\\b", "a\x00b", "a\nb"} {
		if _, err := paths.UploadSelector(filename); err == nil {
			t.Fatalf("UploadSelector(%q) accepted a non-basename", filename)
		}
	}
}

func TestNormalizeRejectsTraversalInEveryForm(t *testing.T) {
	paths := DefaultWorkspacePaths()
	for _, value := range []string{"../etc", "a/../../b", "a/./b", "/home/dr-agent/workspace/../secret"} {
		if _, err := paths.Normalize(value); err == nil {
			t.Fatalf("Normalize(%q) accepted traversal", value)
		}
	}
	for _, value := range []string{"/home/dr-agent/workspace", "/root/workspace/"} {
		relative, err := paths.Normalize(value)
		if err != nil || relative != "" {
			t.Fatalf("Normalize(%q) = %q, %v", value, relative, err)
		}
	}
}
