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

func TestE7ReadmeCommandContract(t *testing.T) {
	raw, err := os.ReadFile("../../README.md")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, command := range []string{"create", "pause", "resume", "resize", "force-restart", "delete", "rename", "status", "operations wait", "operations cancel", "operations retry", "operations continue"} {
		if _, ok := commandRegistry[command]; !ok {
			t.Errorf("missing command %s", command)
		}
	}
	for _, contract := range []string{"--assigned-user UUID", "--creation-team UUID", "--accepted-offer UUID", "If-Match", "/api/v1/daemons/bulk/stop", "complete UUID/revision set", "15 minutes", "Content stays on the device"} {
		if !strings.Contains(text, contract) {
			t.Errorf("missing documentation %s", contract)
		}
	}
	if strings.Contains(text, "spawn NAME --server") || strings.Contains(text, "daemons servers list") {
		t.Error("README advertises removed commands")
	}
}
