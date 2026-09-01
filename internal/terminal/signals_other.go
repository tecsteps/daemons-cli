//go:build !darwin && !linux

package terminal

import "os"

func WatchSignals() (<-chan os.Signal, func()) {
	channel := make(chan os.Signal)
	return channel, func() {}
}

func WatchResize(_ *os.File) (<-chan Size, func()) {
	channel := make(chan Size)
	return channel, func() {}
}

func exitCodeForSignal(_ os.Signal) int {
	return 1
}
