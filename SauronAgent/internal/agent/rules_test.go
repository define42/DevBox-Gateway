package agent

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/define42/SauronAgent/internal/audit"
)

func TestRuleSetupFailurePreventsCollection(t *testing.T) {
	want := errors.New("kernel refused audit configuration")
	a, err := New(Options{
		Config: testConfig("127.0.0.1:1"),
		ConfigureRules: func(context.Context) error {
			return want
		},
		Source: func(context.Context, chan<- *audit.Record) error {
			t.Error("collection started despite rule setup failure")
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Run(t.Context()); !errors.Is(err, want) {
		t.Fatalf("Run = %v, want rule setup failure", err)
	}
	if got := a.metrics.EventsCreated.Load(); got != 0 {
		t.Errorf("created %d events before rule setup succeeded", got)
	}
}

func TestRulesConfiguredBeforeCollection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	configured := false
	collected := false
	a, err := New(Options{
		Config: testConfig("127.0.0.1:1"),
		ConfigureRules: func(setupCtx context.Context) error {
			if _, ok := setupCtx.Deadline(); !ok {
				t.Error("rule setup did not inherit the run deadline")
			}
			configured = true
			return nil
		},
		Source: func(context.Context, chan<- *audit.Record) error {
			collected = true
			if !configured {
				t.Error("collection started before rule setup")
			}
			cancel()
			return nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Run(ctx); err != nil {
		t.Fatal(err)
	}
	if !configured || !collected {
		t.Fatalf("configured=%t collected=%t, want both", configured, collected)
	}
}

func TestRuleSetupSkippedWhenDisabled(t *testing.T) {
	for _, tc := range []struct {
		name    string
		enabled bool
		managed bool
	}{
		{name: "external policy", enabled: true, managed: false},
		{name: "audit disabled", enabled: false, managed: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := testConfig("127.0.0.1:1")
			cfg.Audit.Enabled = tc.enabled
			cfg.Audit.ManageRules = tc.managed
			a, err := New(Options{
				Config: cfg,
				ConfigureRules: func(context.Context) error {
					t.Error("disabled rule setup ran")
					return nil
				},
				Source: newRecordSource().run,
			})
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = a.Close() })
			ctx, cancel := context.WithCancel(t.Context())
			cancel()
			if err := a.Run(ctx); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestRuleSetupReceivesCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	var setupErr error
	a, err := New(Options{
		Config: testConfig("127.0.0.1:1"),
		ConfigureRules: func(setupCtx context.Context) error {
			setupErr = setupCtx.Err()
			return setupErr
		},
		Source: newRecordSource().run,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = a.Close() })
	if err := a.Run(ctx); err != nil {
		t.Fatalf("Run = %v, want orderly cancellation", err)
	}
	if !errors.Is(setupErr, context.Canceled) {
		t.Fatalf("rule setup received %v, want cancellation", setupErr)
	}
}
