package app

import (
	"context"
	"strings"

	"github.com/tecsteps/daemons-cli/internal/errs"
)

type commandHandler func(context.Context, []string, globalOptions, Dependencies) runResult

var commandRegistry = map[string]commandHandler{
	"login":           errorHandler(login),
	"logout":          errorHandler(logout),
	"whoami":          errorHandler(whoami),
	"capabilities":    errorHandler(capabilities),
	"servers list":    errorHandler(listServers),
	"servers show":    errorHandler(showServer),
	"list":            errorHandler(listDaemons),
	"ls":              errorHandler(listDaemons),
	"daemons list":    errorHandler(listDaemons),
	"show":            errorHandler(showDaemon),
	"daemons show":    errorHandler(showDaemon),
	"start":           startDaemon,
	"daemons start":   startDaemon,
	"stop":            stopDaemon,
	"daemons stop":    stopDaemon,
	"restart":         restartDaemon,
	"daemons restart": restartDaemon,
	"retry":           retryDaemon,
	"daemons retry":   retryDaemon,
	"spawn":           spawnDaemon,
	"daemons spawn":   spawnDaemon,
	"destroy":         destroyDaemon,
	"daemons destroy": destroyDaemon,
	"operations list": errorHandler(listOperations),
	"operations show": showOperation,
	"attach":          errorHandler(attach),
	"upload":          uploadFiles,
}

func dispatch(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
	for prefixLength := min(2, len(arguments)); prefixLength >= 1; prefixLength-- {
		name := strings.Join(arguments[:prefixLength], " ")
		if handler, ok := commandRegistry[name]; ok {
			return handler(ctx, arguments[prefixLength:], options, dependencies)
		}
	}
	return runResultFor(errs.New("usage_error", "Unsupported command. Run daemons help.", 2))
}

func errorHandler(handler func(context.Context, []string, globalOptions, Dependencies) error) commandHandler {
	return func(ctx context.Context, arguments []string, options globalOptions, dependencies Dependencies) runResult {
		return runResultFor(handler(ctx, arguments, options, dependencies))
	}
}

func helpRequested(arguments []string) bool {
	return len(arguments) == 1 && (arguments[0] == "--help" || arguments[0] == "-h")
}
