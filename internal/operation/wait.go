// Package operation polls Control Plane operations until they reach a
// terminal state. It is the `--wait` primitive for every mutation command.
package operation

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"strconv"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	DefaultTimeout     = 10 * time.Minute
	defaultInterval    = 2 * time.Second
	defaultMaxInterval = 15 * time.Second
)

// Poller is the read primitive used between polls; *client.Client satisfies it.
type Poller interface {
	ShowOperation(ctx context.Context, operationID string) (client.OperationEnvelope, error)
}

type Options struct {
	Timeout     time.Duration
	Interval    time.Duration
	MaxInterval time.Duration
	Now         func() time.Time
	Sleep       func(context.Context, time.Duration) error
	// Jitter bounds the random spread added to a computed delay. Nil uses
	// up to 25 percent of the delay; tests inject a deterministic function.
	Jitter func(time.Duration) time.Duration
	// Progress is called after every poll that returned an operation.
	Progress func(client.Operation)
}

// IsTerminal reports whether a canonical operation status will never change.
func IsTerminal(status string) bool {
	switch status {
	case "succeeded", "failed", "partially_succeeded", "cancelled", "timed_out", "outcome_unknown":
		return true
	}
	return false
}

// Wait polls the operation until it is terminal, the timeout elapses, or the
// context is cancelled. The returned envelope is always the last document the
// caller can render, even when err is non-nil. Wait never cancels remotely.
func Wait(ctx context.Context, poller Poller, initial client.OperationEnvelope, options Options) (client.OperationEnvelope, error) {
	options = withDefaults(options)
	last := initial
	if IsTerminal(last.Data.Status) {
		return last, nil
	}

	deadline := options.Now().Add(options.Timeout)
	delay := options.Interval
	for {
		remaining := deadline.Sub(options.Now())
		if remaining <= 0 {
			return last, timeout(last.Data, options.Timeout)
		}
		pause := nextDelay(last.RetryAfter, delay, options)
		if pause > remaining {
			pause = remaining
		}
		if err := options.Sleep(ctx, pause); err != nil {
			return last, errs.NewOperation(
				"wait_interrupted",
				fmt.Sprintf("Stopped waiting for operation %s; it continues on the server. Check it with: daemons operations show %s", last.Data.ID, last.Data.ID),
				last.Data.Status,
				1,
			)
		}
		if !options.Now().Before(deadline) {
			return last, timeout(last.Data, options.Timeout)
		}

		next, err := poller.ShowOperation(ctx, last.Data.ID)
		if err != nil {
			if errors.Is(ctx.Err(), context.Canceled) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return last, errs.NewOperation("wait_interrupted", fmt.Sprintf("Stopped waiting for operation %s; it continues on the server.", last.Data.ID), last.Data.Status, 1)
			}
			return last, err
		}
		last = next
		if options.Progress != nil {
			options.Progress(last.Data)
		}
		if IsTerminal(last.Data.Status) {
			return last, nil
		}
		delay = min(delay*3/2, options.MaxInterval)
	}
}

func timeout(operation client.Operation, limit time.Duration) error {
	return errs.NewOperation(
		"wait_timeout",
		fmt.Sprintf("Operation %s was still %s after %s; its outcome is unknown to this client. Check it with: daemons operations show %s", operation.ID, operation.Status, limit, operation.ID),
		operation.Status,
		8,
	)
}

func nextDelay(retryAfter string, delay time.Duration, options Options) time.Duration {
	if seconds, err := strconv.Atoi(retryAfter); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	return delay + options.Jitter(delay)
}

func withDefaults(options Options) Options {
	if options.Timeout <= 0 {
		options.Timeout = DefaultTimeout
	}
	if options.Interval <= 0 {
		options.Interval = defaultInterval
	}
	if options.MaxInterval < options.Interval {
		options.MaxInterval = max(defaultMaxInterval, options.Interval)
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.Sleep == nil {
		options.Sleep = func(ctx context.Context, duration time.Duration) error {
			timer := time.NewTimer(duration)
			defer timer.Stop()
			select {
			case <-timer.C:
				return nil
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}
	if options.Jitter == nil {
		options.Jitter = func(delay time.Duration) time.Duration {
			if delay <= 0 {
				return 0
			}
			return time.Duration(rand.Int64N(int64(delay) / 4))
		}
	}
	return options
}
