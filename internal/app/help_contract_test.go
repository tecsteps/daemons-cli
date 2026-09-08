package app

import (
	"strings"
	"testing"
)

// TestHelpAdvertisesOnlyDispatchableCommands guards the gap that left "servers
// list" and "servers show" in the help text after E7 withdrew them: help named
// a verb that dispatch could not reach, so the CLI documented a usage error.
func TestHelpAdvertisesOnlyDispatchableCommands(t *testing.T) {
	dispatchable := map[string]bool{}
	for name := range commandRegistry {
		dispatchable[strings.Fields(name)[0]] = true
	}
	inCommands := false
	for _, line := range strings.Split(help, "\n") {
		if strings.TrimSpace(line) == "Commands:" {
			inCommands = true
			continue
		}
		if !inCommands {
			continue
		}
		if strings.TrimSpace(line) == "" {
			break
		}
		// Alternatives are separated by a spaced pipe; a bare pipe inside the
		// first token lists interchangeable verbs (start|stop|restart).
		for _, alternative := range strings.Split(strings.TrimSpace(line), " | ") {
			fields := strings.Fields(alternative)
			if len(fields) == 0 {
				continue
			}
			for _, verb := range strings.Split(fields[0], "|") {
				if verb == "" || strings.HasPrefix(verb, "-") || verb != strings.ToLower(verb) {
					continue
				}
				if !dispatchable[verb] {
					t.Errorf("help advertises %q but no registry command starts with it", verb)
				}
			}
		}
	}
}
