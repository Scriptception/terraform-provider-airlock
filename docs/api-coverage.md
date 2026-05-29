# Airlock API Coverage

Source: Airlock Digital REST API v6.1.2+ public Postman documentation.

## Terraform resources

- Allowlist application packages: `airlock_application`
- Application categories: `airlock_application_category`
- Baselines: `airlock_baseline`
- Blocklists: `airlock_blocklist`
- Policy groups: `airlock_group`
- Group allowlist/baseline/blocklist approvals: `airlock_group_application_policy`, `airlock_group_baseline_policy`, `airlock_group_blocklist_policy`
- Group path/process/publisher rules: `airlock_group_path`, `airlock_group_process`, `airlock_group_publisher`

## Terraform data sources

- `airlock_applications`
- `airlock_application_categories`
- `airlock_baselines`
- `airlock_blocklists`
- `airlock_groups`
- `airlock_agents`

## Intentionally not modeled as resources

- Agent download/move/remove: operational endpoint.
- OTP retrieve/revoke/usage/activity: short-lived operational access workflow.
- Exception approve/deny: ticket/workflow action rather than durable desired state.
- License set/get: sensitive licensing workflow.
- Logging and execution history: reporting/audit data.
- Export endpoints: file/export actions.
- Hash inventory and hash package membership: add/remove endpoints need a reliable read/import path before they are safe Terraform resources.

Metarule endpoints are documented for future expansion; they require additional live validation of update/delete/read semantics before being exposed as stateful resources.
