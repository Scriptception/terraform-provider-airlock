resource "airlock_blocklist_metarule" "example" {
  package_id = "1700000001"
  name       = "tf-example-block-metarule"
  os         = "windows"

  criteria = [
    {
      field     = "path"
      operation = "wildcard"
      value     = "C:\\Temp\\*"
    }
  ]

  settings_json = jsonencode({
    notification      = 1
    notification_text = ""
    upload            = 1
  })
}
