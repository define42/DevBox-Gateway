# Testing and linting

```sh
make test     # go test ./... with coverage; writes coverage.out and coverage.html
make lint     # golangci-lint for the gateway; go vet for SauronAgent
make gosec    # gosec security scanner for the gateway
go test -race -p=1 -timeout=15m ./...
```

The test commands include both the gateway and SauronAgent packages, with
combined coverage in `make test`. To run only the SauronAgent tests, use
`make -C SauronAgent test`. The gateway's strict lint and gosec checks cover
`./cmd/...` and `./internal/...`; SauronAgent uses `go vet` through `make lint`.
Run `go vet ./...` to vet the entire module.

Keep `-p=1` when running the full test suite because integration tests in
multiple packages share the system libvirt daemon. Allow extra time for VM
image copies when using the race detector.

Some integration tests (e.g. `ldap_integration_test.go`,
`dashboard_vm_integration_test.go`) start temporary services via
`testcontainers-go`, so Docker needs to be available locally to run them.
