package app

import (
	"context"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"
	"text/tabwriter"

	"github.com/tecsteps/daemons-cli/internal/client"
	"github.com/tecsteps/daemons-cli/internal/errs"
)

const (
	taskRunUsage    = "Usage: daemons task run DAEMON (PROMPT | -) [--agent AGENT] [--model MODEL] [--permission-mode yolo|approval-auto-deny] [--working-directory /workspace/DIR] [--timeout SECONDS] [--idempotency-key KEY]"
	taskShowUsage   = "Usage: daemons task show DAEMON TASK"
	taskCancelUsage = "Usage: daemons task cancel DAEMON TASK [--idempotency-key KEY]"
	taskListUsage   = "Usage: daemons task list DAEMON [--limit N]"
	maximumPrompt   = 100000
)

var permissionModes = map[string]bool{"yolo": true, "approval-auto-deny": true}

var workingDirectoryPattern = regexp.MustCompile(`^/workspace(/[^/\x00-\x1f\\]+)*$`)

// resolveDaemonID accepts a daemon UUID as-is and resolves an exact name
// through the daemon list. Tasks, files, and logs are all nested under the
// daemon, so every Phase 3 command starts here.
func resolveDaemonID(ctx context.Context, api *client.Client, value string) (string, error) {
	if value == "" {
		return "", errs.New("usage_error", "A daemon UUID or exact name is required.", 2)
	}
	if uuidPattern.MatchString(value) {
		return value, nil
	}
	daemon, err := api.ResolveDaemon(ctx, value)
	if err != nil {
		return "", err
	}
	return daemon.ID, nil
}

func runTask(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, taskRunUsage)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, []string{"--agent", "--model", "--permission-mode", "--working-directory", "--timeout"}, taskRunUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if flags.Wait {
		return runResultFor(errs.New("usage_error", "task run has no --wait: the Control Plane exposes no task event route yet. Poll with daemons task show.", 2))
	}
	if len(flags.Positionals) != 2 || flags.Positionals[0] == "" {
		return runResultFor(errs.New("usage_error", taskRunUsage, 2))
	}
	request := client.TaskRequest{
		Agent:            flags.Values["--agent"],
		Model:            flags.Values["--model"],
		PermissionMode:   flags.Values["--permission-mode"],
		WorkingDirectory: flags.Values["--working-directory"],
	}
	if request.PermissionMode != "" && !permissionModes[request.PermissionMode] {
		return runResultFor(errs.New("usage_error", "--permission-mode must be yolo or approval-auto-deny.", 2))
	}
	if request.WorkingDirectory != "" && !safeWorkingDirectory(request.WorkingDirectory) {
		return runResultFor(errs.New("usage_error", "--working-directory must be /workspace or a plain path below it.", 2))
	}
	if timeout, present := flags.Values["--timeout"]; present {
		parsed, parseErr := strconv.Atoi(timeout)
		if parseErr != nil || parsed < 1 {
			return runResultFor(errs.New("usage_error", "--timeout must be a whole number of seconds of at least 1.", 2))
		}
		request.TimeoutSeconds = parsed
	}
	request.Prompt, err = readPrompt(flags.Positionals[1], dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}

	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID, err := resolveDaemonID(ctx, api, flags.Positionals[0])
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{
		Check:          "daemons task list " + flags.Positionals[0],
		Replay:         "daemons task run " + flags.Positionals[0] + " -",
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.CreateTask(ctx, daemonID, request, flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
	} else {
		writeTask(dependencies, result.Data)
		fmt.Fprintf(dependencies.ErrorOutput, "Check progress with: daemons task show %s %s\n", flags.Positionals[0], result.Data.ID)
	}
	return runResult{}
}

// readPrompt returns the positional prompt, or the whole of stdin when the
// operand is "-". The stdin form keeps prompts out of shell history and
// process listings. The prompt itself is never echoed or logged.
func readPrompt(operand string, dependencies Dependencies) (string, error) {
	prompt := operand
	if operand == "-" {
		raw, err := io.ReadAll(io.LimitReader(dependencies.Input, maximumPrompt+1))
		if err != nil {
			return "", errs.New("prompt_unreadable", "Could not read the prompt from stdin.", 2)
		}
		prompt = strings.TrimRight(string(raw), "\r\n")
	}
	if strings.TrimSpace(prompt) == "" {
		return "", errs.New("usage_error", "The prompt is empty. Pass it as an argument or as - to read it from stdin.", 2)
	}
	if len(prompt) > maximumPrompt {
		return "", errs.New("prompt_too_long", "The prompt exceeds the 100000 character limit.", 2)
	}
	return prompt, nil
}

func safeWorkingDirectory(value string) bool {
	if !workingDirectoryPattern.MatchString(value) {
		return false
	}
	for _, segment := range strings.Split(strings.TrimPrefix(value, "/workspace"), "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}

func showTask(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, taskShowUsage)
		return runResult{}
	}
	if len(arguments) != 2 || arguments[0] == "" || arguments[1] == "" {
		return runResultFor(errs.New("usage_error", taskShowUsage, 2))
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID, err := resolveDaemonID(ctx, api, arguments[0])
	if err != nil {
		return runResultFor(err)
	}
	result, err := api.ShowTask(ctx, daemonID, arguments[1])
	if err != nil {
		return runResultFor(err)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
	} else {
		writeTask(dependencies, result.Data)
	}
	return taskResult(result.Data, options.JSON)
}

func cancelTask(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, taskCancelUsage)
		return runResult{}
	}
	flags, err := parseMutationFlags(arguments, nil, taskCancelUsage, options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	if flags.Wait || len(flags.Positionals) != 2 || flags.Positionals[0] == "" || flags.Positionals[1] == "" {
		return runResultFor(errs.New("usage_error", taskCancelUsage, 2))
	}
	if err := ensureIdempotencyKey(&flags, options, dependencies); err != nil {
		return runResultFor(err)
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return runResultFor(err)
	}
	daemonID, err := resolveDaemonID(ctx, api, flags.Positionals[0])
	if err != nil {
		return runResultFor(err)
	}
	guide := reconcileGuide{
		Check:          "daemons task show " + flags.Positionals[0] + " " + flags.Positionals[1],
		Replay:         "daemons task cancel " + flags.Positionals[0] + " " + flags.Positionals[1],
		IdempotencyKey: flags.IdempotencyKey,
	}
	result, err := api.CancelTask(ctx, daemonID, flags.Positionals[1], flags.IdempotencyKey)
	if err != nil {
		return mutationFailure(err, options, dependencies, guide)
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return runResult{}
	}
	writeTask(dependencies, result.Data)
	if cancellation, _ := result.Meta["cancellation"].(string); cancellation == "cancellation_requested_process_may_remain" {
		fmt.Fprintln(dependencies.ErrorOutput, "Cancellation was requested; the agent process may keep running briefly. Check again with daemons task show.")
	}
	return runResult{}
}

func listTasks(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) error {
	if helpRequested(arguments) {
		fmt.Fprintln(dependencies.Output, taskListUsage)
		return nil
	}
	if len(arguments) < 1 || arguments[0] == "" {
		return errs.New("usage_error", taskListUsage, 2)
	}
	limit, err := parseLimit(arguments[1:], taskListUsage)
	if err != nil {
		return err
	}
	api, _, _, err := authenticatedClient(options, dependencies)
	if err != nil {
		return err
	}
	daemonID, err := resolveDaemonID(ctx, api, arguments[0])
	if err != nil {
		return err
	}
	result, err := api.ListTasks(ctx, daemonID, limit)
	if err != nil {
		return err
	}
	if options.JSON {
		writeCanonicalJSON(dependencies.Output, result.Raw)
		return nil
	}
	writer := tabwriter.NewWriter(dependencies.Output, 0, 4, 2, ' ', 0)
	fmt.Fprintln(writer, "ID\tSTATUS\tAGENT\tCREATED")
	for _, task := range result.Data {
		fmt.Fprintf(writer, "%s\t%s\t%s\t%s\n", task.ID, task.Status, task.Agent, task.CreatedAt)
	}
	return writer.Flush()
}

// parseLimit parses an optional trailing "--limit N" (1 to 200) and rejects
// anything else.
func parseLimit(arguments []string, usage string) (int, error) {
	limit := 0
	for index := 0; index < len(arguments); index++ {
		if arguments[index] != "--limit" {
			return 0, errs.New("usage_error", usage, 2)
		}
		if index+1 >= len(arguments) {
			return 0, errs.New("usage_error", "--limit requires a value.", 2)
		}
		parsed, err := strconv.Atoi(arguments[index+1])
		if err != nil || parsed < 1 || parsed > 200 {
			return 0, errs.New("usage_error", "--limit must be a whole number between 1 and 200.", 2)
		}
		limit = parsed
		index++
	}
	return limit, nil
}

// taskResult maps a task's terminal state to the exit contract the same way
// operations do: definite failures exit 1 under the task's error code.
func taskResult(task client.Task, alreadyReported bool) runResult {
	switch task.Status {
	case "failed", "cancelled", "timed_out":
		code := "task_" + task.Status
		if task.ErrorCode != nil && *task.ErrorCode != "" {
			code = *task.ErrorCode
		}
		err := errs.NewOperation(code, fmt.Sprintf("Task %s ended with status %s.", task.ID, task.Status), task.Status, 1)
		return runResult{code: 1, err: err, reported: alreadyReported}
	}
	return runResult{}
}

func writeTask(dependencies Dependencies, task client.Task) {
	fmt.Fprintf(dependencies.Output, "Task %s: %s (%s, %s)\n", task.ID, task.Status, task.Agent, task.PermissionMode)
	if task.WorkingDirectory != "" {
		fmt.Fprintf(dependencies.Output, "  working_directory: %s\n", task.WorkingDirectory)
	}
	if task.ErrorCode != nil && *task.ErrorCode != "" {
		fmt.Fprintf(dependencies.Output, "  error_code: %s\n", sanitizeText(*task.ErrorCode))
	}
	for _, key := range sortedKeys(task.Result) {
		if sensitiveField(key) {
			continue
		}
		fmt.Fprintf(dependencies.Output, "  result.%s: %s\n", key, sanitizeText(fmt.Sprint(task.Result[key])))
	}
	for _, stamp := range []struct {
		label string
		value *string
	}{{"started_at", task.StartedAt}, {"finished_at", task.FinishedAt}} {
		if stamp.value != nil && *stamp.value != "" {
			fmt.Fprintf(dependencies.Output, "  %s: %s\n", stamp.label, *stamp.value)
		}
	}
}
