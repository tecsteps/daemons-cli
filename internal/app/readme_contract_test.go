package app

import (
	"os"
	"strings"
	"testing"
)

func TestMacOSQuarantineInstructionIsConditional(t *testing.T) {
	readme, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(readme)
	check := `xattr -p com.apple.quarantine "$HOME/.local/bin/daemons"`
	remove := `xattr -d com.apple.quarantine "$HOME/.local/bin/daemons"`
	conditional := "if " + check + " >/dev/null 2>&1; then\n       " + remove
	if !strings.Contains(text, conditional) {
		t.Fatalf("README quarantine instructions are not conditional")
	}
}
