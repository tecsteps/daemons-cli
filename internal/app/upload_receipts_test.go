package app

import (
	"bytes"
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestUploadReceiptCommandHelpAndValidationBeforeAuthentication(t *testing.T) {
	for _, test := range []struct {
		args []string
		code int
	}{
		{[]string{"files", "receipt", "--help"}, 0},
		{[]string{"files", "receipt"}, 2},
		{[]string{"files", "receipt", "workspace", "invalid"}, 2},
	} {
		var output, errorOutput bytes.Buffer
		dependencies := phaseOneDependencies(t, http.DefaultClient, &output, &errorOutput)
		if code := Run(context.Background(), test.args, dependencies); code != test.code {
			t.Fatalf("receipt command exit %d, want %d", code, test.code)
		}
		if !strings.Contains(output.String()+errorOutput.String(), "files receipt DAEMON OPERATION") {
			t.Fatal("missing receipt usage")
		}
	}
}
