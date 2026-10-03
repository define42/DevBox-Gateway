// Command devbox-gateway serves the HTTPS dashboard and RDP gateway until an
// interrupt, termination signal, or listener failure ends the process.
package main

import (
	"context"
	"os"
	"os/signal"
	"syscall"

	"github.com/define42/devbox-gateway/internal/gateway"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := gateway.Run(ctx)
	stop()
	os.Exit(exitCode)
}
