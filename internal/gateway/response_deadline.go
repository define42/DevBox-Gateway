package gateway

import (
	"errors"
	"log"
	"net/http"
	"time"

	"github.com/define42/devbox-gateway/internal/config"
)

const defaultHTTPWriteTimeout = 10 * time.Second

func httpWriteTimeout(settings *config.Settings) time.Duration {
	if timeout := settings.Duration(config.TIMEOUT); timeout > 0 {
		return timeout
	}
	return defaultHTTPWriteTimeout
}

// renewableWriteDeadline bounds each write and flush without counting time
// spent provisioning a VM or receiving an authenticated base image upload.
// Keep it local to those handlers; ordinary responses use Server.WriteTimeout.
type renewableWriteDeadline struct {
	http.ResponseWriter

	controller *http.ResponseController
	timeout    time.Duration
	err        error
}

func withRenewableWriteDeadline(w http.ResponseWriter, timeout time.Duration) http.ResponseWriter {
	return &renewableWriteDeadline{
		ResponseWriter: w,
		controller:     http.NewResponseController(w),
		timeout:        timeout,
	}
}

func (w *renewableWriteDeadline) renew() error {
	if w.err != nil {
		return w.err
	}
	err := w.controller.SetWriteDeadline(time.Now().Add(w.timeout))
	if err != nil && !errors.Is(err, http.ErrNotSupported) {
		w.err = err
	}
	return w.err
}

func (w *renewableWriteDeadline) WriteHeader(status int) {
	if err := w.renew(); err != nil {
		log.Printf("set HTTP response write deadline: %v", err)
		return
	}
	w.ResponseWriter.WriteHeader(status)
}

func (w *renewableWriteDeadline) Write(p []byte) (int, error) {
	if err := w.renew(); err != nil {
		return 0, err
	}
	return w.ResponseWriter.Write(p)
}

func (w *renewableWriteDeadline) FlushError() error {
	if err := w.renew(); err != nil {
		return err
	}
	return w.controller.Flush()
}

func (w *renewableWriteDeadline) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}
