# Provider development guide

This repository is a public, tenant-neutral Terraform provider for Airlock Digital.
Keep implementation, documentation, examples, tests, commits, and releases generic.

## Non-negotiable boundaries

- Never commit real tenant URLs, API keys, object names, user or host inventory, live
  responses, state, plans, logs, credentials, or customer-specific workflow details.
- Use the public Airlock REST API documentation and verified API behaviour. Do not guess
  mutation paths, parameters, response fields, or delete semantics.
- Fail closed when a write contract or read-back contract is incomplete. An explicit
  unsupported diagnostic is safer than a best-effort mutation.
- Model durable desired state as resources. Keep reporting, export, approval, OTP,
  licensing, and other short-lived operations as data sources or documented exclusions.
- A mutable resource must have safe create, read, update, delete, import, and drift
  behaviour. Verify successful mutations by reading the intended outcome when the API
  supports it.
- Acceptance mutation tests may run only against an isolated disposable tenant with
  `AIRLOCK_ACC_MUTATION=1`. Read-only acceptance tests must never create, move, approve,
  deny, remove, or reconfigure anything.

## Repository layout

- `internal/client`: typed REST client methods and response parsing.
- `internal/provider`: Terraform Plugin Framework resources and data sources.
- `examples`: runnable, generic Terraform examples.
- `docs`: generated Registry documentation plus the API coverage map.
- `.github/workflows`: test and signed-release automation.

## Change workflow

1. Confirm the exact public API contract and classify the endpoint as durable,
   read-only, or operational.
2. Add or update the client method, provider schema and lifecycle, focused unit tests,
   and a generic example.
3. Regenerate documentation after every schema or example change.
4. Update `docs/api-coverage.md` and `CHANGELOG.md` when coverage or behaviour changes.
5. Run the smallest relevant checks, then the complete release gate before changing
   `VERSION` for a release.

```sh
gofmt -w <changed-go-files>
go test ./internal/client ./internal/provider
make generate
git diff --check

# Complete release gate
go test ./...
go build ./...
govulncheck ./...
git diff --check
```

Do not hand-edit generated schema sections in `docs/`; change the schema or example and
run `make generate`. Never bypass a generated-doc diff.

## Releases

- Keep the exact semantic version in `VERSION` and add the matching changelog heading.
- Merge the tested `VERSION` change to `main`; do not push release tags manually.
- After the exact `main` test workflow succeeds, the release workflow verifies the
  commit and version, creates the matching tag, and runs GoReleaser. A manual dispatch
  safely retries an interrupted release without moving an existing tag.
- Verify the test workflow, release workflow, checksums, signature, manifest, and latest
  published version before considering a release complete.
