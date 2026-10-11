// Command eolscan checks upstream security support for SBOM dependencies.
package main

import (
	"context"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/Pirikara/eolscan/internal/cli"
)

func main() { os.Exit(run()) }

func run() int {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	return cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, &http.Client{}, time.Now().UTC())
}
