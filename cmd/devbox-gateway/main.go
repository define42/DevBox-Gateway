package main

import (
	"context"
	"devboxgateway/internal/gateway"
	"os"
	"os/signal"
	"syscall"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	exitCode := gateway.Run(ctx)
	stop()
	os.Exit(exitCode)
}
