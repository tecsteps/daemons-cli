package app

import "testing"

func TestSSHProxyControlFramesAreStable(t *testing.T) {
	if sshControlReady != `{"type":"ready"}` || sshControlEOF != `{"type":"eof"}` {
		t.Fatalf("unexpected SSH control frames: %q %q", sshControlReady, sshControlEOF)
	}
}
