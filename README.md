# Terraform Provider for Airlock Digital

Terraform provider for managing durable Airlock Digital application control configuration.

This provider is built with the Terraform Plugin Framework and targets the Airlock Digital REST API v6.1.2+.

## Example

```hcl
terraform {
  required_providers {
    airlock = {
      source = "Scriptception/airlock"
    }
  }
}

provider "airlock" {
  url = "https://airlock.example.com:3129"
  # Prefer AIRLOCK_API_KEY instead of putting credentials in configuration.
}
```

## Environment variables

- `AIRLOCK_URL`
- `AIRLOCK_API_KEY`
- `AIRLOCK_INSECURE`
- `AIRLOCK_TIMEOUT_SECONDS`

## Scope

The provider manages durable configuration surfaces such as allowlist applications, application categories, baselines, blocklists, policy groups, group policy relationships, trusted paths/processes/publishers, and hash relationships.

Imperative, sensitive, or reporting-style API endpoints such as OTP issue/revoke, exception approval, logs, license mutation, agent download/removal, and exports are intentionally not modeled as Terraform resources.
