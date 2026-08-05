resource "airlock_application_metarule" "example" {
  package_id = "1700000000"
  name       = "tf-example-allow-metarule"
  os         = "windows"

  criteria = [
    {
      field     = "publisher"
      operation = "match"
      value     = "Example Publisher"
    }
  ]

  settings_json = jsonencode({
    upload = 1
  })
}
