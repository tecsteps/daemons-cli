package main

import (
	"context"
	"os"

	"github.com/tecsteps/daemons-cli/internal/app"
)

var version = "dev"

func main() {
	os.Exit(app.Run(context.Background(), os.Args[1:], app.Dependencies{Version: version}))
}
