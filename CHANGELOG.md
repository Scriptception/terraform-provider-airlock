# Changelog

## 0.2.0

- Replaced opaque group policy JSON with typed Airlock 6.1.4 settings and drift readback. Existing `settings_json` configuration must be converted to typed attributes during upgrade. Proxy passwords and agent stop codes are now write-only values with explicit version triggers.
- Changed application and blocklist hash membership to one authoritative complete-set resource per package. Canonical imports use `application:<target_id>` and `blocklist:<target_id>`. Existing v0.1 three-part chunk IDs must be removed from state and re-imported before refresh or mutation.
- Kept baseline hash membership additive so externally managed and reference baseline content is not removed.
- Added typed, ordered metarule criteria with canonical state migration from `criteria_json`. Convert existing metarule HCL to typed `criteria` during upgrade to keep the migrated state aligned without replacement.
- Made agent assignment destroy fail closed unless a fallback group is configured, moved to, and verified.
- Added blocklist relationship audit readback and explicit `proxy_url` / `AIRLOCK_PROXY_URL` support while preserving standard environment proxy behaviour when unset.
- Updated Terraform Framework dependencies and the Go toolchain baseline.

## 0.1.2

Added endpoint agent policy group assignment management with `airlock_agent_group_assignment`, backed by Airlock agent move/find APIs.

## 0.1.1

Fixed relationship resource import/read handling for schema-specific attributes, and changed hash membership drift detection to use package export readback instead of hash query membership inference.

## 0.1.0

Expanded durable Airlock administration coverage with group settings, metarules, hash repository and package membership resources, group policy and supporting administration data sources, reference baseline lookup/import support, and an API coverage map.

## 0.0.9

Initial provider implementation for Airlock Digital REST API v6.1.2+ with 11 resources, 6 data sources, import support, generated documentation, and signed-release automation.
