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
