# Airlock API Coverage

Source: Airlock Digital REST API v6.1.4+ public Postman documentation.

## Terraform resources

- Allowlist application packages: `airlock_application`
- Application categories: `airlock_application_category`
- Allowlist metarules: `airlock_application_metarule`
- Baselines: `airlock_baseline`
- Blocklists: `airlock_blocklist`
- Blocklist metarules: `airlock_blocklist_metarule`
- Policy groups: `airlock_group`
- Endpoint agent policy group assignment: `airlock_agent_group_assignment`
- Policy group settings: `airlock_group_settings`
- Group allowlist/baseline/blocklist approvals: `airlock_group_application_policy`, `airlock_group_baseline_policy`, `airlock_group_blocklist_policy`
- Group path/process/publisher rules: `airlock_group_path`, `airlock_group_process`, `airlock_group_publisher`
- Hash repository and package membership: `airlock_hash`, `airlock_application_hashes`, `airlock_baseline_hashes`, `airlock_blocklist_hashes`

## Resource semantics

- `airlock_group_settings` reads the complete durable Airlock 6.1.4 group policy settings through typed attributes. It writes only audit mode, script control, poll time, PowerShell lockdown, proxy configuration, notifications, reflection, and communication-list settings using verified granular contracts. Unsupported differences and agent stop-code changes fail before any mutation. Proxy passwords are write-only with an explicit version trigger. Destroy removes Terraform state only and does not reset the live settings.
- `airlock_application_hashes` and `airlock_blocklist_hashes` each manage the complete hash set for one package. Use one resource per package.
- `airlock_baseline_hashes` is additive. It does not remove baseline or reference baseline content managed outside that resource.
- `airlock_application_metarule` and `airlock_blocklist_metarule` apply one typed criterion add, update, or delete without replacing the metarule when the plan requires exactly one mutation call. Known combined name-and-criteria changes and multi-criterion changes are rejected during planning and must be split into separate applies; the same guard runs before Update for values that were previously unknown. Criteria IDs remain server-only and are not stored in Terraform state. Immediately before the mutation, the provider requires live criteria IDs to be present and unique, requires indexes to be ordered and contiguous, and compares live values and order with refreshed prior state. An update uses the immediate preflight ID; readback verifies the desired final values and all surviving preflight IDs. Airlock does not provide conditional writes for these endpoints, so concurrent console or API writes during apply are unsupported. Package, operating-system, legacy `criteria_json`, and recorded `settings_json` changes retain their existing replacement behaviour.
- `airlock_agent_group_assignment` requires an explicit fallback policy group on destroy, then moves and verifies the agent before removing state.

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
- `airlock_cloud_groups`
- `airlock_reference_baselines`
- `airlock_hash_query`

## Internal helper endpoints

- Application, baseline, and blocklist export endpoints are used as readback helpers for hash membership. Application and blocklist exports provide authoritative complete-set drift detection. Baseline exports verify the additive hashes managed by the resource. The exports are not exposed as standalone resources because they are file actions rather than durable desired state.
- Agent move and find endpoints are used to manage and verify endpoint-to-policy-group assignment. Agent removal and download remain out of scope.

## Intentionally not modeled as resources

- Agent download and removal: operational endpoint.
- OTP retrieve/revoke/usage/activity: short-lived operational access workflow.
- Exception approve/deny: ticket/workflow action rather than durable desired state.
- License set/get: sensitive licensing workflow.
- Logging and execution history: reporting/audit data.
- Standalone export resources: file/export actions.
