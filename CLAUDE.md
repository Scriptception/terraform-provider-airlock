# CLAUDE.md

Guidance for future contributors working on this provider.

- Do not commit real Airlock URLs, API keys, object names, hostnames, users, log output, or live response fixtures.
- Use Terraform Plugin Framework protocol v6.
- Keep durable configuration as resources and reporting/imperative endpoints as data sources or documented out-of-scope items.
- Acceptance tests must create disposable `tf-acc-` objects and clean them up.
- Regenerate docs with `make generate` after schema or examples change.
