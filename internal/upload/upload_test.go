package upload

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateOpensAllRegularFilesBeforeUpload(t *testing.T) {
	directory := t.TempDir()
	first := filepath.Join(directory, "first.txt")
	second := filepath.Join(directory, "second.txt")
	for _, name := range []string{first, second} {
		if err := os.WriteFile(name, []byte("ok"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	files, err := Validate([]string{first, second}, directory)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(files)
	if len(files) != 2 || files[0].Filename != "first.txt" || files[1].Filename != "second.txt" {
		t.Fatalf("Validate() = %#v", files)
	}
}

func TestValidateRejectsDirectoryBeforeOpeningAnyUpload(t *testing.T) {
	_, err := Validate([]string{t.TempDir()}, t.TempDir())
	if err == nil {
		t.Fatal("Validate() accepted a directory")
	}
}

func TestValidateRejectsOversizedFiles(t *testing.T) {
	file, err := os.Create(filepath.Join(t.TempDir(), "large.bin"))
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(MaxFileSize + 1); err != nil {
		t.Fatal(err)
	}
	file.Close()

	_, err = Validate([]string{file.Name()}, t.TempDir())
	if err == nil {
		t.Fatal("Validate() accepted an oversized file")
	}
}

func TestSafeUploadPath(t *testing.T) {
	for _, value := range []string{
		"/root/workspace/uploads/note.txt",
		"/root/workspace/uploads/design note.png",
	} {
		if !safeUploadPath(value) {
			t.Fatalf("safeUploadPath(%q) = false", value)
		}
	}
	for _, value := range []string{
		"/root/workspace/uploads/../secret",
		"/root/workspace/other/note.txt",
		"relative.txt",
		"/root/workspace/uploads/note.txt\nunsafe",
	} {
		if safeUploadPath(value) {
			t.Fatalf("safeUploadPath(%q) = true", value)
		}
	}
}

func TestTildeResolution(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home shorthand")
	}
	home := t.TempDir()
	filePath := filepath.Join(home, "note.txt")
	if err := os.WriteFile(filePath, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	files, err := Validate([]string{"~/note.txt"}, home)
	if err != nil {
		t.Fatal(err)
	}
	defer Close(files)
	if files[0].Path != filePath {
		t.Fatalf("resolved path = %s, want %s", files[0].Path, filePath)
	}
}
