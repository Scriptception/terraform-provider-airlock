# Airlock API Coverage

Source: Airlock Digital REST API v6.1.2+ public Postman documentation.

## Terraform resources

- Allowlist application packages: `airlock_application`
- Application categories: `airlock_application_category`
- Allowlist metarules: `airlock_application_metarule`
- Baselines: `airlock_baseline`
- Blocklists: `airlock_blocklist`
- Blocklist metarules: `airlock_blocklist_metarule`
- Policy groups: `airlock_group`
- Policy group settings: `airlock_group_settings`
- Group allowlist/baseline/blocklist approvals: `airlock_group_application_policy`, `airlock_group_baseline_policy`, `airlock_group_blocklist_policy`
- Group path/process/publisher rules: `airlock_group_path`, `airlock_group_process`, `airlock_group_publisher`
- Hash repository and package membership: `airlock_hash`, `airlock_application_hashes`, `airlock_baseline_hashes`, `airlock_blocklist_hashes`

## Terraform data sources

- `airlock_applications`
- `airlock_application_categories`
- `airlock_baselines`
- `airlock_blocklists`
- `airlock_groups`
- `airlock_agents`
- `airlock_group_policy`
- `airlock_group_agents`
- `airlock_communication_lists`
- `airlock_domain_groups`
- `airlock_reference_baselines`
- `airlock_hash_query`

## Internal helper endpoints

- Application, baseline, and blocklist export endpoints are used as readback helpers for hash membership drift detection. They are intentionally not exposed as standalone Terraform resources because they are file/export actions rather than durable desired state.

## Intentionally not modeled as resources

- Agent download/move/remove: operational endpoint.
- OTP retrieve/revoke/usage/activity: short-lived operational access workflow.
- Exception approve/deny: ticket/workflow action rather than durable desired state.
- License set/get: sensitive licensing workflow.
- Logging and execution history: reporting/audit data.
- Standalone export resources: file/export actions.
