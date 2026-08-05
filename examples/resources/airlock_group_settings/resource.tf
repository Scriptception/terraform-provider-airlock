# Terraform writes only settings with verified granular Airlock API contracts.
# Keep the remaining required values equal to the live group; unsupported
# differences are rejected before any setting is changed.
resource "airlock_group_settings" "example" {
  group_id = "00000000-0000-0000-0000-000000000000"

  audit_mode                  = 0
  script_control              = 1
  command_line_enabled        = 1
  batch                       = 1
  powershell                  = 1
  command                     = 1
  vbscript                    = 1
  javascript                  = 1
  windows_installer           = 1
  html_applications           = 1
  java_applications           = 1
  windows_script_component    = 1
  compiled_html               = 1
  shell_script                = 1
  dylib                       = 1
  python                      = 1
  scpt                        = 1
  script_custom               = 1
  module_reload               = 1
  poll_time                   = 300
  powershell_lockdown         = 2
  proxy_enabled               = 0
  proxy_server                = ""
  proxy_port                  = ""
  proxy_authentication        = 0
  proxy_username              = ""
  notifications_enabled       = 1
  notification_message        = "This file was blocked by policy."
  generalisation              = 0
  browser                     = 2
  mac_trusted_installer       = 1
  microsoft_trusted_installer = 1
  trusted_upload              = 0
  trusted_config              = false
  self_service                = 0
  custom_otp                  = []
  self_upgrade                = 0
  windows_agent_version       = ""
  linux_agent_version         = ""
  macos_agent_version         = ""
  reflection                  = 0
  communication_list_id       = "airlock-default-communication-list"
}
