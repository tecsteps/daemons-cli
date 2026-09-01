package app

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
	"github.com/tecsteps/daemons-cli/internal/operation"
)

// reconcileGuide tells the user what to run when a mutation's outcome is
// unknown. The CLI never replays a possibly destructive or billable mutation
// on its own; it only names the safe check and the key a replay must reuse.
type reconcileGuide struct {
	Check          string
	Replay         string
	IdempotencyKey string
}

func (guide reconcileGuide) write(dependencies Dependencies) {
	if guide.Check == "" {
		return
	}
	fmt.Fprintf(dependencies.ErrorOutput, "Reconcile before retrying: %s\n", guide.Check)
	if guide.Replay != "" && guide.IdempotencyKey != "" {
		fmt.Fprintf(dependencies.ErrorOutput, "If the change is missing, replay with the same key: %s --idempotency-key %s\n", guide.Replay, guide.IdempotencyKey)
	}
	fmt.Fprintln(dependencies.ErrorOutput, "Never retry under a new idempotency key.")
}

// mutationFailure renders a failed mutation request. Confirmation refusals
// get the web-approval presentation and exit 6; unknown outcomes get the
// reconciliation guidance and exit 8; everything else follows the standard
// error path.
func mutationFailure(err error, options globalOptions, dependencies Dependencies, guide reconcileGuide) runResult {
	var apiError *errs.APIError
	if errors.As(err, &apiError) && apiError.Code == "confirmation_required" {
		return presentConfirmation(apiError, options, dependencies)
	}
	if errs.ExitCode(err) == 8 {
		writeError(dependencies, options.JSON, err)
		guide.write(dependencies)
		return runResult{code: 8, err: err, reported: true}
	}
	return runResultFor(err)
}

// presentConfirmation shows a confirmation_required refusal. The request had
// no side effect. In JSON or non-interactive mode the canonical problem is
// written and nothing is opened; interactively the CLI offers to open the
// approval URL, and opening it is never treated as consent.
func presentConfirmation(apiError *errs.APIError, options globalOptions, dependencies Dependencies) runResult {
	result := runResult{code: 6, err: apiError, reported: true}
	if options.JSON {
		writeError(dependencies, true, apiError)
		return result
	}

	approveURL, _ := apiError.Meta["approve_url"].(string)
	expiresAt, _ := apiError.Meta["expires_at"].(string)
	confirmationID, _ := apiError.Meta["confirmation_id"].(string)
	fmt.Fprintf(dependencies.ErrorOutput, "Web confirmation required: %s\n", sanitizeText(apiError.Error()))
	if approveURL != "" {
		fmt.Fprintf(dependencies.ErrorOutput, "Approve at: %s\n", sanitizeText(approveURL))
	}
	if expiresAt != "" {
		fmt.Fprintf(dependencies.ErrorOutput, "Expires: %s\n", expiresAt)
	}
	if confirmationID != "" {
		fmt.Fprintf(dependencies.ErrorOutput, "Confirmation ID: %s\n", confirmationID)
	}
	fmt.Fprintln(dependencies.ErrorOutput, "No change was made. After approving in the browser, run this command again.")

	if !dependencies.IsInteractive() || dependencies.OpenURL == nil || !safeBrowserURL(approveURL) {
		return result
	}
	fmt.Fprint(dependencies.ErrorOutput, "Open the approval URL in your browser? [y/N] ")
	answer, _ := bufio.NewReader(dependencies.Input).ReadString('\n')
	if answer = strings.ToLower(strings.TrimSpace(answer)); answer != "y" && answer != "yes" {
		return result
	}
	if openErr := dependencies.OpenURL(approveURL); openErr != nil {
		fmt.Fprintln(dependencies.ErrorOutput, "Could not open a browser; open the URL above manually.")
	}
	return result
}

func safeBrowserURL(value string) bool {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.User != nil {
		return false
	}
	return parsed.Scheme == "https" || (parsed.Scheme == "http" && isLoopback(parsed.Hostname()))
}

func isLoopback(host string) bool {
	return strings.EqualFold(host, "localhost") || strings.HasPrefix(host, "127.") || host == "::1"
}

// finishOperation renders the operation a mutation returned and, with --wait,
// polls it to a terminal state. Every rendered document is canonical in JSON
// mode; progress and guidance go to stderr.
func finishOperation(ctx context.Context, api *client.Client, initial client.OperationEnvelope, flags mutationFlags, options globalOptions, dependencies Dependencies, guide reconcileGuide) runResult {
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, initial.Raw)
	} else {
		writeOperation(dependencies, initial.Data)
	}
	if !flags.Wait {
		return operationOutcome(initial.Data, options, dependencies, guide)
	}
	return waitForOperation(ctx, api, initial, flags, options, dependencies, guide)
}

func waitForOperation(ctx context.Context, api *client.Client, initial client.OperationEnvelope, flags mutationFlags, options globalOptions, dependencies Dependencies, guide reconcileGuide) runResult {
	if operation.IsTerminal(initial.Data.Status) {
		return operationOutcome(initial.Data, options, dependencies, guide)
	}
	if !options.Quiet {
		fmt.Fprintf(dependencies.ErrorOutput, "Waiting for operation %s (timeout %s, Ctrl-C stops waiting without cancelling)...\n", initial.Data.ID, flags.WaitTimeout)
	}
	lastStatus := initial.Data.Status
	final, err := operation.Wait(ctx, api, initial, operation.Options{
		Timeout: flags.WaitTimeout,
		Now:     dependencies.Now,
		Sleep:   dependencies.Sleep,
		Progress: func(current client.Operation) {
			if !options.Quiet && current.Status != lastStatus {
				fmt.Fprintf(dependencies.ErrorOutput, "Operation %s: %s\n", current.ID, current.Status)
				lastStatus = current.Status
			}
		},
	})
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, final.Raw)
	} else {
		writeOperation(dependencies, final.Data)
	}
	if err != nil {
		fmt.Fprintf(dependencies.ErrorOutput, "Error [%s]: %s\n", errs.Code(err), sanitizeText(err.Error()))
		if errs.ExitCode(err) == 8 {
			guide.write(dependencies)
		}
		return runResult{code: errs.ExitCode(err), err: err, reported: true}
	}
	return operationOutcome(final.Data, options, dependencies, guide)
}

// operationOutcome maps a rendered operation's terminal state to the exit
// contract and adds human guidance for partial and unknown outcomes.
func operationOutcome(current client.Operation, options globalOptions, dependencies Dependencies, guide reconcileGuide) runResult {
	result := operationResult(current, options.JSON)
	if result.err == nil {
		return result
	}
	if !options.JSON {
		fmt.Fprintf(dependencies.ErrorOutput, "Error [%s]: %s\n", errs.Code(result.err), sanitizeText(result.err.Error()))
	}
	switch current.Status {
	case "partially_succeeded":
		fmt.Fprintf(dependencies.ErrorOutput, "The operation only partly succeeded; inspect its result above and the resource before retrying.\n")
	case "outcome_unknown":
		guide.write(dependencies)
	}
	result.reported = true
	return result
}

func writeOperation(dependencies Dependencies, current client.Operation) {
	fmt.Fprintf(dependencies.Output, "Operation %s: %s (%s)\n", current.ID, current.Status, current.Type)
	if current.Resource != nil && current.Resource.ID != "" {
		fmt.Fprintf(dependencies.Output, "  resource: %s %s\n", current.Resource.Type, current.Resource.ID)
	}
	if current.ErrorCode != nil && *current.ErrorCode != "" {
		fmt.Fprintf(dependencies.Output, "  error_code: %s\n", sanitizeText(*current.ErrorCode))
	}
	for _, key := range sortedKeys(current.Result) {
		fmt.Fprintf(dependencies.Output, "  result.%s: %s\n", key, sanitizeText(fmt.Sprint(current.Result[key])))
	}
}
