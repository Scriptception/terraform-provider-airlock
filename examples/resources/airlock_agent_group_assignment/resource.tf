resource "airlock_agent_group_assignment" "example" {
  agent_id                  = "00000000-0000-0000-0000-000000000000"
  group_id                  = "11111111-1111-1111-1111-111111111111"
  destroy_fallback_group_id = "22222222-2222-2222-2222-222222222222"
}
