# Terraform Provider for Airlock Digital

[![Tests](https://github.com/Scriptception/terraform-provider-airlock/actions/workflows/test.yml/badge.svg?branch=main)](https://github.com/Scriptception/terraform-provider-airlock/actions/workflows/test.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/Scriptception/terraform-provider-airlock.svg)](https://pkg.go.dev/github.com/Scriptception/terraform-provider-airlock)
[![License: MPL 2.0](https://img.shields.io/badge/License-MPL_2.0-brightgreen.svg)](./LICENSE)
[![Go version](https://img.shields.io/github/go-mod/go-version/Scriptception/terraform-provider-airlock)](./go.mod)

Manage [Airlock Digital](https://www.airlockdigital.com/) application control configuration as code.

> **Independent project.** This is an unofficial, independent community provider built against Airlock Digital's publicly available REST API reference and verified API behavior. It is not affiliated with, endorsed by, sponsored by, or maintained by Airlock Digital or any employer, customer, or client of the maintainer. The provider requires an Airlock tenant URL and API key supplied by the user; no proprietary customer data, internal systems, or non-public implementation details are included.

- **18 resources** for allowlist applications, categories, metarules, baselines, blocklists, policy groups, group settings, group policy relationships, trusted path/process/publisher rules, and hash membership.
- **12 data sources** for reading existing Airlock configuration, group policy, group agents, communication lists, domain groups, reference baselines, hash membership, and inventory.
- Built on [terraform-plugin-framework](https://developer.hashicorp.com/terraform/plugin/framework) (protocol v6).
- Targets the Airlock Digital REST API v6.1.2+.

> **Scope.** This provider manages durable administrative configuration that belongs in source control. Short-lived, operational, reporting, or sensitive workflows such as OTP retrieval, exception approval, logs, license mutation, agent download/removal, and exports are intentionally not modeled as Terraform resources. See [docs/api-coverage.md](./docs/api-coverage.md) for the current API coverage map.

## Requirements

- [Terraform](https://developer.hashicorp.com/terraform/downloads) 1.11+
- Airlock Digital REST API v6.1.2+
- An Airlock API key with permissions for the resources you want to manage
- [Go](https://go.dev/doc/install) 1.24+ only if building from source

## Quick start

```hcl
terraform {
  required_providers {
    airlock = {
      source  = "Scriptception/airlock"
      version = "~> 0.1"
    }
  }
}

provider "airlock" {
  url = "https://airlock.example.com:3129"

  # Prefer AIRLOCK_API_KEY instead of putting credentials in configuration.
  # insecure = true # for self-signed certs; or set AIRLOCK_INSECURE=true
}
```

Provider settings also accept environment variables: `AIRLOCK_URL`, `AIRLOCK_API_KEY`, `AIRLOCK_INSECURE`, and `AIRLOCK_TIMEOUT_SECONDS`.

## Walkthrough

A small example showing how to create a policy group, a baseline package, a blocklist package, and attach both packages to the group:

```hcl
resource "airlock_group" "servers" {
  name   = "tf-example-windows-servers"
  hidden = false
}

resource "airlock_baseline" "windows_servers" {
  name = "tf-example-windows-server-baseline"
}

resource "airlock_blocklist" "security_blocklist" {
  name = "tf-example-security-blocklist"
}

resource "airlock_group_baseline_policy" "servers_baseline" {
  group_id  = airlock_group.servers.id
  target_id = airlock_baseline.windows_servers.id
}

resource "airlock_group_blocklist_policy" "servers_blocklist" {
  group_id  = airlock_group.servers.id
  target_id = airlock_blocklist.security_blocklist.id
  audit     = true
}

resource "airlock_group_path" "trusted_tooling" {
  group_id = airlock_group.servers.id
  value    = "C:\\Program Files\\Example\\*"
  comment  = "Example trusted tooling path"
}
```

## Resources and data sources

Full reference docs live under [`docs/`](./docs) and on the Terraform Registry once published.

| Resource | What it manages |
| --- | --- |
| `airlock_agent_group_assignment` | Endpoint agent assignment to an Airlock policy group. |
| `airlock_application` | Allowlist application packages. |
| `airlock_application_category` | Application categories and subcategories. |
| `airlock_application_metarule` | Allowlist metarules with ordered criteria. |
| `airlock_application_hashes` | Hash membership for an allowlist package. |
| `airlock_baseline` | Baseline packages. |
| `airlock_baseline_hashes` | Hash membership for a baseline package. |
| `airlock_blocklist` | Blocklist packages. |
| `airlock_blocklist_metarule` | Blocklist metarules with ordered criteria. |
| `airlock_blocklist_hashes` | Hash membership for a blocklist package. |
| `airlock_group` | Airlock policy groups. |
| `airlock_group_settings` | Durable settings for an Airlock policy group. |
| `airlock_group_application_policy` | Application approval for a policy group. |
| `airlock_group_baseline_policy` | Baseline approval for a policy group. |
| `airlock_group_blocklist_policy` | Blocklist approval for a policy group. |
| `airlock_group_path` | Trusted path entries on a policy group. |
| `airlock_group_process` | Parent or grandparent process rules on a policy group. |
| `airlock_group_publisher` | Trusted publisher entries on a policy group. |
| `airlock_hash` | SHA256 hash registration in the Airlock repository. |

Data sources:

- `airlock_agents`
- `airlock_application_categories`
- `airlock_applications`
- `airlock_baselines`
- `airlock_blocklists`
- `airlock_communication_lists`
- `airlock_domain_groups`
- `airlock_group_agents`
- `airlock_group_policy`
- `airlock_groups`
- `airlock_hash_query`
- `airlock_reference_baselines`

## Authentication and secret handling

Create an Airlock API key with the minimum permissions required for the configuration you manage. Export it as `AIRLOCK_API_KEY` or pass it via the `api_key` provider attribute.

The provider marks `api_key` as `Sensitive`, so Terraform does not print it in plan/apply output. Do not hardcode API keys in `.tf` files. Prefer:

- environment variables such as `AIRLOCK_API_KEY`
- `*.tfvars` files kept out of git
- a secrets backend such as [HashiCorp Vault](https://developer.hashicorp.com/terraform/tutorials/secrets/secrets-vault), [SOPS](https://github.com/getsops/sops), [Doppler](https://docs.doppler.com/docs/terraform), or [1Password](https://developer.1password.com/docs/terraform)

## Development

```sh
make build      # compile
make install    # go install to $GOBIN, useful with Terraform dev_overrides
make test       # unit tests, no network
make testacc    # acceptance tests; mutation tests also require AIRLOCK_ACC_MUTATION=1
make generate   # regenerate docs/ from schema + examples/
make lint       # golangci-lint
make vuln       # govulncheck
make fmt        # gofmt
```

Read-only acceptance tests require `AIRLOCK_URL`, `AIRLOCK_API_KEY`, and `TF_ACC=1`. Mutation acceptance tests additionally require `AIRLOCK_ACC_MUTATION=1` and should only be run against an isolated Airlock environment with disposable `tf-acc-*` objects. Never commit live Airlock URLs, API keys, hostnames, user details, group names, or response fixtures.

See [CLAUDE.md](./CLAUDE.md) for architecture notes, API scope decisions, and conventions for adding new resources.

## Contributing

Issues and PRs welcome. If you add a new resource, verify the live Airlock API behavior before coding. The public Postman documentation is the source of truth for endpoint discovery, but Terraform resources still need read/import/delete behavior that is safe and durable.

Follow the existing conventions: typed client methods in `internal/client`, Framework resources and data sources in `internal/provider`, generated docs under `docs/`, and runnable examples under `examples/`.

## License

[Mozilla Public License 2.0](./LICENSE).
