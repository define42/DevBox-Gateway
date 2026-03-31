# Repository Guidelines

## Project Structure & Module Organization
This repository is a Go module for an HTTPS RDP gateway. Core application entrypoints and handlers live at the repository root (`main.go`, `handlers.go`, `dashboard.go`, `console.go`), with supporting packages under `internal/`.

UI source lives in `ui/`, and the compiled browser asset is `static/dashboard.js`. LDAP fixtures for local development and tests live in `testldap/`. Most tests are root-level `*_test.go` files, including integration coverage such as `integration_test.go`, `ldap_integration_test.go`, and `novnc_page_test.go`.

## Build, Test, and Development Commands
- `make run`: stop any existing stack, build the Docker images, and start the local gateway + LDAP services with Docker Compose.
- `make test`: run all Go tests with coverage across packages.
- `make lint`: run `golangci-lint`.
- `make gosec`: run `gosec`.
- `tsc -p tsconfig.json`: rebuild the dashboard TypeScript bundle into `static/dashboard.js`.

## Local Run And Login Flow
For a full local UI run, use `make run`. The gateway listens on `https://localhost` and, when no cert/key are provided, generates a self-signed certificate for the session.

When automating the UI with Playwright:
- open `https://localhost`
- bypass the browser privacy warning by choosing `Advanced` and then `Proceed to localhost (unsafe)`
- sign in with username `johndoe` and password `dogood`
- a successful login lands on `/api/dashboard`

These credentials are also exercised by the LDAP integration tests, so they are the preferred local smoke-test account.

## Coding Style & Naming Conventions
Use standard Go formatting with `gofmt` and keep naming idiomatic:
- exported identifiers use `PascalCase`
- unexported identifiers use `camelCase`
- test files use the `*_test.go` convention

Keep handlers and helpers focused. Prefer table-driven tests for branching behavior, and keep UI assets named by feature.

## Testing Guidelines
Use Go's `testing` package for unit and integration coverage. Some integration tests start temporary services with `testcontainers-go`, so Docker needs to be available.

Before submitting changes, run at minimum:
- `make test`

If linting, auth, or request handling changed, also run:
- `make lint`
- `go test -race ./...`

## Commit & Pull Request Guidelines
Keep commits single-purpose and use short, specific commit messages. PRs should include a concise summary, commands run locally, and screenshots when the dashboard or login flow changes.

## Security & Configuration Tips
Do not commit real certificates, private keys, or production LDAP endpoints. Local development uses a self-signed certificate and test LDAP credentials only.

All environment-backed parameters must be defined in `internal/config/config.go`. When adding or changing env parameters, always use the configuration pattern from `config.go` instead of reading environment variables directly in feature code.
Global parameters are not allowed. This is validated with `make lint`.
