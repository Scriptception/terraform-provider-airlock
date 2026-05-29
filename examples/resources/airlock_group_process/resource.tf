resource "airlock_group_process" "example" {
  group_id = "1700000004"
  type     = "pprocess"
  value    = "example.exe"
  comment  = "Example parent process"
}
