package main

import (
	"strings"
	"testing"
)

func stubDashboardVMOwnershipCheck(t *testing.T, fn func(name, username string) (bool, error)) {
	t.Helper()

	originalCheck := dashboardVMOwnershipCheck
	dashboardVMOwnershipCheck = fn
	t.Cleanup(func() {
		dashboardVMOwnershipCheck = originalCheck
	})
}

func stubDashboardVMOwnershipByPrefix(t *testing.T) {
	t.Helper()

	stubDashboardVMOwnershipCheck(t, func(name, username string) (bool, error) {
		return strings.HasPrefix(name, username+"-"), nil
	})
}
