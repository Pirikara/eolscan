// Command eolscan checks upstream security support for SBOM dependencies.
package main

import (
	"context"
	"fmt"
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
	done := make(chan int, 1)
	go func() {
		done <- cli.Run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, &http.Client{}, time.Now().UTC())
	}()
	select {
	case code := <-done:
		if ctx.Err() != nil {
			return 130
		}
		return code
	case <-ctx.Done():
		// Allow ordinary cancellation to close input and clean up. A blocked
		// filesystem or output stream must not prevent process termination.
		timer := time.NewTimer(250 * time.Millisecond)
		defer timer.Stop()
		select {
		case <-done:
		case <-timer.C:
			fmt.Fprintln(os.Stderr, "scan interrupted:", ctx.Err())
		}
		return 130
	}
}
