resource "airlock_group_settings" "example" {
  group_id = "00000000-0000-0000-0000-000000000000"

  settings_json = jsonencode({
    auditmode            = 0
    script_enabled       = 1
    batch                = 1
    powershell           = 1
    command              = 1
    vbscript             = 1
    javascript           = 1
    windowsinstaller     = 1
    htmlapplications     = 1
    javaapplications     = 1
    windowsscriptcomponent = 1
    compiledhtml         = 1
    shellscript          = 1
    dylib                = 1
    python               = 1
    poll_time            = 300
    pslockdown           = 2
    proxyenabled         = 0
    enable_notifications = 1
    notification_message = "This file was blocked by policy."
    agentstopcode        = ""
    generalisation       = 0
    browser              = 2
    mitrustedinstaller   = 1
    trusted_upload       = 0
    selfupgrade          = 0
    reflection           = 0
    commlistid           = "airlock-default-communication-list"
  })
}
