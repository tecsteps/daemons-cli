package operation

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

type fakePoller struct {
	responses []client.OperationEnvelope
	err       error
	calls     int
}

func (poller *fakePoller) ShowOperation(context.Context, string) (client.OperationEnvelope, error) {
	poller.calls++
	if poller.err != nil {
		return client.OperationEnvelope{}, poller.err
	}
	index := min(poller.calls-1, len(poller.responses)-1)
	return poller.responses[index], nil
}

func envelope(status, retryAfter string) client.OperationEnvelope {
	return client.OperationEnvelope{Data: client.Operation{ID: "op", Type: "daemon.start", Status: status}, RetryAfter: retryAfter}
}

func fakeClock(start time.Time) (func() time.Time, func(context.Context, time.Duration) error, *[]time.Duration) {
	now := start
	sleeps := []time.Duration{}
	return func() time.Time { return now }, func(_ context.Context, duration time.Duration) error {
		sleeps = append(sleeps, duration)
		now = now.Add(duration)
		return nil
	}, &sleeps
}

func TestWaitReturnsTerminalInitialWithoutPolling(t *testing.T) {
	poller := &fakePoller{}
	final, err := Wait(context.Background(), poller, envelope("succeeded", ""), Options{})
	if err != nil || poller.calls != 0 || final.Data.Status != "succeeded" {
		t.Fatalf("err = %v, calls = %d, status = %q", err, poller.calls, final.Data.Status)
	}
}

func TestWaitPollsUntilTerminalHonouringRetryAfter(t *testing.T) {
	now, sleep, sleeps := fakeClock(time.Unix(0, 0))
	poller := &fakePoller{responses: []client.OperationEnvelope{envelope("running", "7"), envelope("running", ""), envelope("succeeded", "")}}
	progress := []string{}
	final, err := Wait(context.Background(), poller, envelope("queued", "3"), Options{
		Now: now, Sleep: sleep, Jitter: func(time.Duration) time.Duration { return 0 },
		Progress: func(current client.Operation) { progress = append(progress, current.Status) },
	})
	if err != nil || final.Data.Status != "succeeded" || poller.calls != 3 {
		t.Fatalf("err = %v, status = %q, calls = %d", err, final.Data.Status, poller.calls)
	}
	// Initial Retry-After 3s, then Retry-After 7s, then backoff 4.5s (2s * 1.5 * 1.5).
	want := []time.Duration{3 * time.Second, 7 * time.Second, 4500 * time.Millisecond}
	if len(*sleeps) != len(want) {
		t.Fatalf("sleeps = %v", *sleeps)
	}
	for index := range want {
		if (*sleeps)[index] != want[index] {
			t.Fatalf("sleeps = %v, want %v", *sleeps, want)
		}
	}
	if len(progress) != 3 || progress[2] != "succeeded" {
		t.Fatalf("progress = %v", progress)
	}
}

func TestWaitTimesOutWithUnknownOutcome(t *testing.T) {
	now, sleep, _ := fakeClock(time.Unix(0, 0))
	poller := &fakePoller{responses: []client.OperationEnvelope{envelope("running", "")}}
	final, err := Wait(context.Background(), poller, envelope("queued", ""), Options{
		Timeout: 10 * time.Second, Now: now, Sleep: sleep, Jitter: func(time.Duration) time.Duration { return 0 },
	})
	if errs.Code(err) != "wait_timeout" || errs.ExitCode(err) != 8 {
		t.Fatalf("err = %v, code = %q, exit = %d", err, errs.Code(err), errs.ExitCode(err))
	}
	if final.Data.Status != "running" || poller.calls == 0 {
		t.Fatalf("last status = %q, calls = %d", final.Data.Status, poller.calls)
	}
	if now().Sub(time.Unix(0, 0)) != 10*time.Second {
		t.Fatalf("clock advanced %s, want exactly the timeout", now().Sub(time.Unix(0, 0)))
	}
}

func TestWaitStopsLocallyOnCancelWithoutRemoteCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	poller := &fakePoller{responses: []client.OperationEnvelope{envelope("running", "")}}
	sleep := func(ctx context.Context, _ time.Duration) error {
		cancel()
		return ctx.Err()
	}
	final, err := Wait(ctx, poller, envelope("queued", ""), Options{Sleep: sleep})
	if errs.Code(err) != "wait_interrupted" || errs.ExitCode(err) != 1 || poller.calls != 0 || final.Data.Status != "queued" {
		t.Fatalf("err = %v, calls = %d, status = %q", err, poller.calls, final.Data.Status)
	}
}

func TestWaitSurfacesPollErrors(t *testing.T) {
	want := errors.New("boom")
	poller := &fakePoller{err: want}
	_, err := Wait(context.Background(), poller, envelope("queued", ""), Options{Sleep: func(context.Context, time.Duration) error { return nil }})
	if !errors.Is(err, want) {
		t.Fatalf("err = %v", err)
	}
}

func TestIsTerminal(t *testing.T) {
	for _, status := range []string{"succeeded", "failed", "partially_succeeded", "cancelled", "timed_out", "outcome_unknown"} {
		if !IsTerminal(status) {
			t.Fatalf("%q should be terminal", status)
		}
	}
	for _, status := range []string{"queued", "running", "", "future_state"} {
		if IsTerminal(status) {
			t.Fatalf("%q should not be terminal", status)
		}
	}
}
