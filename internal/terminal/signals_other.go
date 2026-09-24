//go:build !darwin && !linux

package terminal

import (
	"os"
	"os/signal"
)

func WatchSignals() (<-chan os.Signal, func()) {
	channel := make(chan os.Signal, 1)
	signal.Notify(channel, os.Interrupt)
	return channel, func() { signal.Stop(channel) }
}

func WatchResize(_ *os.File) (<-chan Size, func()) {
	channel := make(chan Size)
	return channel, func() {}
}

func exitCodeForSignal(_ os.Signal) int {
	return 1
}
