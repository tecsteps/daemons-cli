package terminal

import (
	"errors"
	"os"

	"github.com/tecsteps/daemons-cli/internal/errs"
	"golang.org/x/term"
)

type Restorer func() error

func Preflight(stdin, stdout *os.File, termName string) (Size, error) {
	if !term.IsTerminal(int(stdin.Fd())) || !term.IsTerminal(int(stdout.Fd())) {
		return Size{}, errs.New("tty_required", "Attach requires interactive stdin and stdout terminals.", 2)
	}
	if termName == "" || termName == "dumb" {
		return Size{}, errs.New("terminal_unsupported", "Attach requires an xterm-compatible terminal.", 2)
	}
	cols, rows, err := term.GetSize(int(stdout.Fd()))
	if err != nil || cols < 2 || rows < 1 {
		return Size{}, errs.New("terminal_size_unavailable", "Attach could not determine the terminal size.", 2)
	}

	return Size{Cols: cols, Rows: rows}, nil
}

func EnterRaw(stdin *os.File) (Restorer, error) {
	state, err := term.MakeRaw(int(stdin.Fd()))
	if err != nil {
		return nil, errs.New("raw_mode_unavailable", "Attach could not enter terminal raw mode.", 2)
	}
	restored := false
	return func() error {
		if restored {
			return nil
		}
		restored = true
		if err := term.Restore(int(stdin.Fd()), state); err != nil {
			return errors.New("could not restore terminal mode")
		}
		return nil
	}, nil
}
