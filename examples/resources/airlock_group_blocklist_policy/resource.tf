resource "airlock_group_blocklist_policy" "example" {
  group_id  = "1700000004"
  target_id = "1700000007"
  audit     = true
}
