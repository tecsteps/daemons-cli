//go:build darwin || linux

package terminal

import (
	"os"
	"os/signal"
	"syscall"

	"golang.org/x/term"
)

func WatchSignals() (<-chan os.Signal, func()) {
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, syscall.SIGHUP, syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTERM)
	return channel, func() { signal.Stop(channel) }
}

func WatchResize(stdout *os.File) (<-chan Size, func()) {
	signals := make(chan os.Signal, 1)
	sizes := make(chan Size, 1)
	signal.Notify(signals, syscall.SIGWINCH)
	done := make(chan struct{})
	go func() {
		for {
			select {
			case <-signals:
				cols, rows, err := term.GetSize(int(stdout.Fd()))
				if err == nil {
					select {
					case sizes <- Size{Cols: cols, Rows: rows}:
					default:
						select {
						case <-sizes:
						default:
						}
						sizes <- Size{Cols: cols, Rows: rows}
					}
				}
			case <-done:
				return
			}
		}
	}()

	return sizes, func() {
		signal.Stop(signals)
		close(done)
	}
}

func exitCodeForSignal(value os.Signal) int {
	if signalValue, ok := value.(syscall.Signal); ok {
		return 128 + int(signalValue)
	}
	return 1
}
