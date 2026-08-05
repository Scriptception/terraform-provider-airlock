package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type groupSettingsResource struct{ configuredResource }

type groupSettingsModel struct {
	ID                        types.String `tfsdk:"id"`
	GroupID                   types.String `tfsdk:"group_id"`
	AuditMode                 types.Int64  `tfsdk:"audit_mode"`
	ScriptControl             types.Int64  `tfsdk:"script_control"`
	CommandLineEnabled        types.Int64  `tfsdk:"command_line_enabled"`
	Batch                     types.Int64  `tfsdk:"batch"`
	PowerShell                types.Int64  `tfsdk:"powershell"`
	Command                   types.Int64  `tfsdk:"command"`
	VBScript                  types.Int64  `tfsdk:"vbscript"`
	JavaScript                types.Int64  `tfsdk:"javascript"`
	WindowsInstaller          types.Int64  `tfsdk:"windows_installer"`
	HTMLApplications          types.Int64  `tfsdk:"html_applications"`
	JavaApplications          types.Int64  `tfsdk:"java_applications"`
	WindowsScriptComponent    types.Int64  `tfsdk:"windows_script_component"`
	CompiledHTML              types.Int64  `tfsdk:"compiled_html"`
	ShellScript               types.Int64  `tfsdk:"shell_script"`
	Dylib                     types.Int64  `tfsdk:"dylib"`
	Python                    types.Int64  `tfsdk:"python"`
	SCPT                      types.Int64  `tfsdk:"scpt"`
	ScriptCustom              types.Int64  `tfsdk:"script_custom"`
	ModuleReload              types.Int64  `tfsdk:"module_reload"`
	PollTime                  types.Int64  `tfsdk:"poll_time"`
	PowerShellLockdown        types.Int64  `tfsdk:"powershell_lockdown"`
	ProxyEnabled              types.Int64  `tfsdk:"proxy_enabled"`
	ProxyServer               types.String `tfsdk:"proxy_server"`
	ProxyPort                 types.String `tfsdk:"proxy_port"`
	ProxyAuthentication       types.Int64  `tfsdk:"proxy_authentication"`
	ProxyUsername             types.String `tfsdk:"proxy_username"`
	ProxyPasswordWO           types.String `tfsdk:"proxy_password_wo"`
	ProxyPasswordWOVersion    types.Int64  `tfsdk:"proxy_password_wo_version"`
	NotificationsEnabled      types.Int64  `tfsdk:"notifications_enabled"`
	NotificationMessage       types.String `tfsdk:"notification_message"`
	AgentStopCodeWO           types.String `tfsdk:"agent_stop_code_wo"`
	AgentStopCodeWOVersion    types.Int64  `tfsdk:"agent_stop_code_wo_version"`
	Generalisation            types.Int64  `tfsdk:"generalisation"`
	Browser                   types.Int64  `tfsdk:"browser"`
	MacTrustedInstaller       types.Int64  `tfsdk:"mac_trusted_installer"`
	MicrosoftTrustedInstaller types.Int64  `tfsdk:"microsoft_trusted_installer"`
	TrustedUpload             types.Int64  `tfsdk:"trusted_upload"`
	TrustedConfig             types.Bool   `tfsdk:"trusted_config"`
	SelfService               types.Int64  `tfsdk:"self_service"`
	CustomOTP                 types.List   `tfsdk:"custom_otp"`
	SelfUpgrade               types.Int64  `tfsdk:"self_upgrade"`
	WindowsAgentVersion       types.String `tfsdk:"windows_agent_version"`
	LinuxAgentVersion         types.String `tfsdk:"linux_agent_version"`
	MacOSAgentVersion         types.String `tfsdk:"macos_agent_version"`
	Reflection                types.Int64  `tfsdk:"reflection"`
	CommunicationListID       types.String `tfsdk:"communication_list_id"`
}

type groupSettingsModelV0 struct {
	ID           types.String `tfsdk:"id"`
	GroupID      types.String `tfsdk:"group_id"`
	SettingsJSON types.String `tfsdk:"settings_json"`
	PolicyJSON   types.String `tfsdk:"policy_json"`
}

func NewGroupSettingsResource() resource.Resource { return &groupSettingsResource{} }

func (r *groupSettingsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_settings"
}

func (r *groupSettingsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = groupSettingsSchema()
}

func groupSettingsSchema() schema.Schema {
	attrs := map[string]schema.Attribute{
		"id":                          schema.StringAttribute{Computed: true, Description: "Airlock policy group ID."},
		"group_id":                    schema.StringAttribute{Required: true, Description: "Airlock policy group ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"audit_mode":                  requiredGroupSettingInt("Policy audit mode."),
		"script_control":              requiredGroupSettingInt("Script control mode. Maps to the Airlock script_enabled setting."),
		"command_line_enabled":        requiredGroupSettingInt("Command-line control mode."),
		"batch":                       requiredGroupSettingInt("Batch script control mode."),
		"powershell":                  requiredGroupSettingInt("PowerShell script control mode."),
		"command":                     requiredGroupSettingInt("Command script control mode."),
		"vbscript":                    requiredGroupSettingInt("VBScript control mode."),
		"javascript":                  requiredGroupSettingInt("JavaScript control mode."),
		"windows_installer":           requiredGroupSettingInt("Windows Installer control mode."),
		"html_applications":           requiredGroupSettingInt("HTML application control mode."),
		"java_applications":           requiredGroupSettingInt("Java application control mode."),
		"windows_script_component":    requiredGroupSettingInt("Windows Script Component control mode."),
		"compiled_html":               requiredGroupSettingInt("Compiled HTML control mode."),
		"shell_script":                requiredGroupSettingInt("Shell script control mode."),
		"dylib":                       requiredGroupSettingInt("Dynamic library control mode."),
		"python":                      requiredGroupSettingInt("Python script control mode."),
		"scpt":                        requiredGroupSettingInt("AppleScript control mode."),
		"script_custom":               requiredGroupSettingInt("Custom script control mode."),
		"module_reload":               requiredGroupSettingInt("Module reload control mode."),
		"poll_time":                   schema.Int64Attribute{Required: true, Description: "Agent polling interval in seconds.", Validators: []validator.Int64{nonNegativeInt64Validator{}}},
		"powershell_lockdown":         requiredGroupSettingInt("PowerShell language mode."),
		"proxy_enabled":               requiredGroupSettingInt("Whether the policy proxy is enabled."),
		"proxy_server":                requiredGroupSettingString("Proxy server name or address. Use an empty string when proxy is disabled."),
		"proxy_port":                  requiredGroupSettingString("Proxy port. Use an empty string when proxy is disabled."),
		"proxy_authentication":        requiredGroupSettingInt("Whether proxy authentication is enabled."),
		"proxy_username":              requiredGroupSettingString("Proxy username. Use an empty string when proxy authentication is disabled."),
		"proxy_password_wo":           schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Proxy password. The value is sent only on create or when proxy_password_wo_version changes, and is never stored in Terraform state."},
		"proxy_password_wo_version":   groupSecretVersionAttribute("Trigger for applying proxy_password_wo. Increment this value when the password changes."),
		"notifications_enabled":       requiredGroupSettingInt("Whether endpoint notifications are enabled."),
		"notification_message":        requiredGroupSettingString("Endpoint notification message."),
		"agent_stop_code_wo":          schema.StringAttribute{Optional: true, Sensitive: true, WriteOnly: true, Description: "Agent stop code. The value is sent only on create or when agent_stop_code_wo_version changes, and is never stored in Terraform state."},
		"agent_stop_code_wo_version":  groupSecretVersionAttribute("Trigger for applying agent_stop_code_wo. Increment this value when the stop code changes."),
		"generalisation":              requiredGroupSettingInt("Agent runtime generalisation mode."),
		"browser":                     requiredGroupSettingInt("Browser control mode."),
		"mac_trusted_installer":       requiredGroupSettingInt("macOS trusted installer mode."),
		"microsoft_trusted_installer": requiredGroupSettingInt("Microsoft Managed Installer trust mode."),
		"trusted_upload":              requiredGroupSettingInt("Trusted execution activity upload mode."),
		"trusted_config":              schema.BoolAttribute{Required: true, Description: "Whether trusted configuration is enabled."},
		"self_service":                requiredGroupSettingInt("Self-service mode."),
		"custom_otp":                  schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "Ordered custom OTP settings."},
		"self_upgrade":                requiredGroupSettingInt("Agent self-upgrade mode."),
		"windows_agent_version":       requiredGroupSettingString("Target Windows agent version. Use an empty string when self-upgrade is disabled."),
		"linux_agent_version":         requiredGroupSettingString("Target Linux agent version. Use an empty string when self-upgrade is disabled."),
		"macos_agent_version":         requiredGroupSettingString("Target macOS agent version. Use an empty string when self-upgrade is disabled."),
		"reflection":                  requiredGroupSettingInt("Assembly reflection prevention mode."),
		"communication_list_id":       requiredGroupSettingString("Communication list ID."),
	}
	return schema.Schema{
		Version:     1,
		Description: "Manage the complete durable settings for an Airlock policy group. Relationship and server-computed policy fields are managed by other resources or omitted. Destroy removes Terraform state only and does not reset live group settings.",
		Attributes:  attrs,
	}
}

func groupSettingsSchemaV0() schema.Schema {
	return schema.Schema{Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true},
		"group_id":      schema.StringAttribute{Required: true},
		"settings_json": schema.StringAttribute{Required: true, Sensitive: true},
		"policy_json":   schema.StringAttribute{Computed: true, Sensitive: true},
	}}
}

func requiredGroupSettingInt(description string) schema.Int64Attribute {
	return schema.Int64Attribute{Required: true, Description: description}
}

func requiredGroupSettingString(description string) schema.StringAttribute {
	return schema.StringAttribute{Required: true, Description: description}
}

func groupSecretVersionAttribute(description string) schema.Int64Attribute {
	return schema.Int64Attribute{
		Optional:    true,
		Computed:    true,
		Default:     int64default.StaticInt64(0),
		Description: description,
		Validators:  []validator.Int64{nonNegativeInt64Validator{}},
	}
}

func (r *groupSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupSettingsModel
	var config groupSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	payload := groupSettingsPayload(plan)
	addConfiguredGroupSecrets(payload, config, true, true)
	if err := r.client.UpdateGroupSettings(ctx, payload); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock group settings", err.Error())
		return
	}
	plan.ID = plan.GroupID
	r.refresh(ctx, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.ProxyPasswordWOVersion.IsNull() || state.ProxyPasswordWOVersion.IsUnknown() {
		state.ProxyPasswordWOVersion = types.Int64Value(0)
	}
	if state.AgentStopCodeWOVersion.IsNull() || state.AgentStopCodeWOVersion.IsUnknown() {
		state.AgentStopCodeWOVersion = types.Int64Value(0)
	}
	r.refresh(ctx, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	state.ID = state.GroupID
	state.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupSettingsModel
	var prior groupSettingsModel
	var config groupSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	proxyChanged := !plan.ProxyPasswordWOVersion.Equal(prior.ProxyPasswordWOVersion)
	stopCodeChanged := !plan.AgentStopCodeWOVersion.Equal(prior.AgentStopCodeWOVersion)
	if proxyChanged && !knownString(config.ProxyPasswordWO) {
		resp.Diagnostics.AddAttributeError(pathRoot("proxy_password_wo"), "Missing proxy password", "Set proxy_password_wo when changing proxy_password_wo_version.")
	}
	if stopCodeChanged && !knownString(config.AgentStopCodeWO) {
		resp.Diagnostics.AddAttributeError(pathRoot("agent_stop_code_wo"), "Missing agent stop code", "Set agent_stop_code_wo when changing agent_stop_code_wo_version.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	payload := groupSettingsPayload(plan)
	addConfiguredGroupSecrets(payload, config, proxyChanged, stopCodeChanged)
	if err := r.client.UpdateGroupSettings(ctx, payload); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock group settings", err.Error())
		return
	}
	plan.ID = plan.GroupID
	r.refresh(ctx, &plan, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.clearWriteOnly()
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupSettingsResource) Delete(ctx context.Context, _ resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}

func (r *groupSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("proxy_password_wo_version"), int64(0))...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("agent_stop_code_wo_version"), int64(0))...)
}

func (r *groupSettingsResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	priorSchema := groupSettingsSchemaV0()
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: &priorSchema,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var prior groupSettingsModelV0
				resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
				if resp.Diagnostics.HasError() {
					return
				}
				next := zeroGroupSettingsModel(prior.GroupID.ValueString())
				next.ID = prior.ID
				settings, err := jsonObject(prior.SettingsJSON.ValueString())
				if err != nil {
					resp.Diagnostics.AddError("Unable to upgrade Airlock group settings state", fmt.Sprintf("settings_json is invalid: %v", err))
					return
				}
				mergeGroupSettings(&next, settings)
				next.clearWriteOnly()
				resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
			},
		},
	}
}

func (r *groupSettingsResource) refresh(ctx context.Context, model *groupSettingsModel, addError func(string, string)) {
	policy, err := r.client.GetGroupPolicyRaw(ctx, model.GroupID.ValueString())
	if err != nil {
		addError("Unable to read Airlock group policy", err.Error())
		return
	}
	next, err := parseLiveGroupSettings(model.GroupID.ValueString(), groupSettingsContainer(policy))
	if err != nil {
		addError("Unable to read Airlock group settings", err.Error())
		return
	}
	next.ProxyPasswordWOVersion = model.ProxyPasswordWOVersion
	next.AgentStopCodeWOVersion = model.AgentStopCodeWOVersion
	next.clearWriteOnly()
	*model = next
}

func groupSettingsPayload(model groupSettingsModel) map[string]any {
	return map[string]any{
		"groupid":                model.GroupID.ValueString(),
		"auditmode":              model.AuditMode.ValueInt64(),
		"script_enabled":         model.ScriptControl.ValueInt64(),
		"cmdline_enabled":        model.CommandLineEnabled.ValueInt64(),
		"batch":                  model.Batch.ValueInt64(),
		"powershell":             model.PowerShell.ValueInt64(),
		"command":                model.Command.ValueInt64(),
		"vbscript":               model.VBScript.ValueInt64(),
		"javascript":             model.JavaScript.ValueInt64(),
		"windowsinstaller":       model.WindowsInstaller.ValueInt64(),
		"htmlapplication":        model.HTMLApplications.ValueInt64(),
		"javaapplication":        model.JavaApplications.ValueInt64(),
		"windowsscriptcomponent": model.WindowsScriptComponent.ValueInt64(),
		"compiledhtml":           model.CompiledHTML.ValueInt64(),
		"shellscript":            model.ShellScript.ValueInt64(),
		"dylib":                  model.Dylib.ValueInt64(),
		"python":                 model.Python.ValueInt64(),
		"scpt":                   model.SCPT.ValueInt64(),
		"script_custom":          model.ScriptCustom.ValueInt64(),
		"modreload":              model.ModuleReload.ValueInt64(),
		"poll_time":              model.PollTime.ValueInt64(),
		"pslockdown":             model.PowerShellLockdown.ValueInt64(),
		"proxyenabled":           model.ProxyEnabled.ValueInt64(),
		"proxyserver":            model.ProxyServer.ValueString(),
		"proxyport":              model.ProxyPort.ValueString(),
		"proxyauth":              model.ProxyAuthentication.ValueInt64(),
		"proxyuser":              model.ProxyUsername.ValueString(),
		"enable_notifications":   model.NotificationsEnabled.ValueInt64(),
		"notification_message":   model.NotificationMessage.ValueString(),
		"generalisation":         model.Generalisation.ValueInt64(),
		"browser":                model.Browser.ValueInt64(),
		"mactrustedinstaller":    model.MacTrustedInstaller.ValueInt64(),
		"mitrustedinstaller":     model.MicrosoftTrustedInstaller.ValueInt64(),
		"trusted_upload":         model.TrustedUpload.ValueInt64(),
		"trusted_config":         model.TrustedConfig.ValueBool(),
		"selfservice":            model.SelfService.ValueInt64(),
		"custom_otp":             stringsFromList(model.CustomOTP),
		"selfupgrade":            model.SelfUpgrade.ValueInt64(),
		"targetvers": []map[string]string{{
			"windows": model.WindowsAgentVersion.ValueString(),
			"linux":   model.LinuxAgentVersion.ValueString(),
			"macos":   model.MacOSAgentVersion.ValueString(),
		}},
		"reflection": model.Reflection.ValueInt64(),
		"commlistid": model.CommunicationListID.ValueString(),
	}
}

func addConfiguredGroupSecrets(payload map[string]any, config groupSettingsModel, includeProxy, includeStopCode bool) {
	if includeProxy && knownString(config.ProxyPasswordWO) {
		payload["proxypass"] = config.ProxyPasswordWO.ValueString()
	}
	if includeStopCode && knownString(config.AgentStopCodeWO) {
		payload["agentstopcode"] = config.AgentStopCodeWO.ValueString()
	}
}

func knownString(value types.String) bool {
	return !value.IsNull() && !value.IsUnknown()
}

func (model *groupSettingsModel) clearWriteOnly() {
	model.ProxyPasswordWO = types.StringNull()
	model.AgentStopCodeWO = types.StringNull()
}

func groupSettingsContainer(policy map[string]any) map[string]any {
	for _, key := range []string{"settings", "group_settings"} {
		if nested, ok := mapValue(policy[key]); ok {
			return nested
		}
	}
	if nested, ok := mapValue(policy["policy"]); ok {
		for _, key := range []string{"settings", "group_settings"} {
			if settings, ok := mapValue(nested[key]); ok {
				return settings
			}
		}
		return nested
	}
	return policy
}

func parseLiveGroupSettings(groupID string, raw map[string]any) (groupSettingsModel, error) {
	model := zeroGroupSettingsModel(groupID)
	intSettings := []struct {
		key    string
		target *types.Int64
	}{
		{"auditmode", &model.AuditMode},
		{"script_enabled", &model.ScriptControl},
		{"cmdline_enabled", &model.CommandLineEnabled},
		{"batch", &model.Batch},
		{"powershell", &model.PowerShell},
		{"command", &model.Command},
		{"vbscript", &model.VBScript},
		{"javascript", &model.JavaScript},
		{"windowsinstaller", &model.WindowsInstaller},
		{"htmlapplication", &model.HTMLApplications},
		{"javaapplication", &model.JavaApplications},
		{"windowsscriptcomponent", &model.WindowsScriptComponent},
		{"compiledhtml", &model.CompiledHTML},
		{"shellscript", &model.ShellScript},
		{"dylib", &model.Dylib},
		{"python", &model.Python},
		{"scpt", &model.SCPT},
		{"script_custom", &model.ScriptCustom},
		{"modreload", &model.ModuleReload},
		{"poll_time", &model.PollTime},
		{"pslockdown", &model.PowerShellLockdown},
		{"proxyenabled", &model.ProxyEnabled},
		{"proxyauth", &model.ProxyAuthentication},
		{"enable_notifications", &model.NotificationsEnabled},
		{"generalisation", &model.Generalisation},
		{"browser", &model.Browser},
		{"mactrustedinstaller", &model.MacTrustedInstaller},
		{"mitrustedinstaller", &model.MicrosoftTrustedInstaller},
		{"trusted_upload", &model.TrustedUpload},
		{"selfservice", &model.SelfService},
		{"selfupgrade", &model.SelfUpgrade},
		{"reflection", &model.Reflection},
	}
	for _, setting := range intSettings {
		value, ok := raw[setting.key]
		if !ok {
			return groupSettingsModel{}, fmt.Errorf("Airlock group settings response omitted required setting %q", setting.key)
		}
		parsed, ok := liveInt64Value(value)
		if !ok {
			return groupSettingsModel{}, fmt.Errorf("Airlock group settings response returned an invalid integer for %q", setting.key)
		}
		*setting.target = types.Int64Value(parsed)
	}

	stringSettings := []struct {
		key    string
		target *types.String
	}{
		{"proxyserver", &model.ProxyServer},
		{"proxyport", &model.ProxyPort},
		{"proxyuser", &model.ProxyUsername},
		{"notification_message", &model.NotificationMessage},
		{"commlistid", &model.CommunicationListID},
	}
	for _, setting := range stringSettings {
		value, ok := raw[setting.key]
		if !ok {
			return groupSettingsModel{}, fmt.Errorf("Airlock group settings response omitted required setting %q", setting.key)
		}
		parsed, ok := value.(string)
		if !ok {
			return groupSettingsModel{}, fmt.Errorf("Airlock group settings response returned an invalid string for %q", setting.key)
		}
		*setting.target = types.StringValue(parsed)
	}

	trustedConfig, ok := raw["trusted_config"]
	if !ok {
		return groupSettingsModel{}, fmt.Errorf("Airlock group settings response omitted required setting %q", "trusted_config")
	}
	trustedConfigBool, ok := trustedConfig.(bool)
	if !ok {
		return groupSettingsModel{}, fmt.Errorf("Airlock group settings response returned an invalid boolean for %q", "trusted_config")
	}
	model.TrustedConfig = types.BoolValue(trustedConfigBool)

	customOTP, ok := raw["custom_otp"]
	if !ok {
		return groupSettingsModel{}, fmt.Errorf("Airlock group settings response omitted required setting %q", "custom_otp")
	}
	customOTPStrings, ok := liveStringSliceValue(customOTP)
	if !ok {
		return groupSettingsModel{}, fmt.Errorf("Airlock group settings response returned an invalid string list for %q", "custom_otp")
	}
	customOTPValues := make([]attr.Value, 0, len(customOTPStrings))
	for _, value := range customOTPStrings {
		customOTPValues = append(customOTPValues, types.StringValue(value))
	}
	model.CustomOTP = types.ListValueMust(types.StringType, customOTPValues)

	targetVersions, ok := raw["targetvers"]
	if !ok {
		return groupSettingsModel{}, fmt.Errorf("Airlock group settings response omitted required setting %q", "targetvers")
	}
	windows, linux, macos, err := parseLiveTargetVersions(targetVersions)
	if err != nil {
		return groupSettingsModel{}, err
	}
	model.WindowsAgentVersion = types.StringValue(windows)
	model.LinuxAgentVersion = types.StringValue(linux)
	model.MacOSAgentVersion = types.StringValue(macos)

	return model, nil
}

func liveInt64Value(value any) (int64, bool) {
	switch value := value.(type) {
	case int:
		return int64(value), true
	case int8:
		return int64(value), true
	case int16:
		return int64(value), true
	case int32:
		return int64(value), true
	case int64:
		return value, true
	case uint:
		if uint64(value) > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case uint8:
		return int64(value), true
	case uint16:
		return int64(value), true
	case uint32:
		return int64(value), true
	case uint64:
		if value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case float64:
		if math.IsNaN(value) || math.IsInf(value, 0) || math.Trunc(value) != value || value < math.MinInt64 || value > math.MaxInt64 {
			return 0, false
		}
		return int64(value), true
	case json.Number:
		parsed, err := value.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func liveStringSliceValue(value any) ([]string, bool) {
	switch value := value.(type) {
	case nil:
		return []string{}, true
	case []string:
		return value, true
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			stringItem, ok := item.(string)
			if !ok {
				return nil, false
			}
			out = append(out, stringItem)
		}
		return out, true
	default:
		return nil, false
	}
}

func parseLiveTargetVersions(value any) (windows, linux, macos string, err error) {
	if value == nil {
		return "", "", "", nil
	}

	var target map[string]any
	switch value := value.(type) {
	case []any:
		if len(value) != 1 {
			return "", "", "", fmt.Errorf("Airlock group settings response returned targetvers with %d entries; expected exactly one or null", len(value))
		}
		target, _ = value[0].(map[string]any)
	case []map[string]any:
		if len(value) != 1 {
			return "", "", "", fmt.Errorf("Airlock group settings response returned targetvers with %d entries; expected exactly one or null", len(value))
		}
		target = value[0]
	case []map[string]string:
		if len(value) != 1 {
			return "", "", "", fmt.Errorf("Airlock group settings response returned targetvers with %d entries; expected exactly one or null", len(value))
		}
		if len(value[0]) != 3 {
			return "", "", "", fmt.Errorf("Airlock group settings response returned an invalid targetvers object; expected exactly windows, linux, and macos")
		}
		windowsValue, windowsOK := value[0]["windows"]
		linuxValue, linuxOK := value[0]["linux"]
		macosValue, macosOK := value[0]["macos"]
		if !windowsOK || !linuxOK || !macosOK {
			return "", "", "", fmt.Errorf("Airlock group settings response returned an invalid targetvers object; expected exactly windows, linux, and macos")
		}
		target = map[string]any{
			"windows": windowsValue,
			"linux":   linuxValue,
			"macos":   macosValue,
		}
	case json.RawMessage:
		var decoded any
		if json.Unmarshal(value, &decoded) != nil {
			return "", "", "", fmt.Errorf("Airlock group settings response returned invalid JSON for targetvers")
		}
		return parseLiveTargetVersions(decoded)
	default:
		return "", "", "", fmt.Errorf("Airlock group settings response returned targetvers in an unsupported structure; expected exactly one object or null")
	}
	if target == nil || len(target) != 3 {
		return "", "", "", fmt.Errorf("Airlock group settings response returned an invalid targetvers object; expected exactly windows, linux, and macos")
	}
	windows, windowsOK := target["windows"].(string)
	linux, linuxOK := target["linux"].(string)
	macos, macosOK := target["macos"].(string)
	if !windowsOK || !linuxOK || !macosOK {
		return "", "", "", fmt.Errorf("Airlock group settings response returned an invalid targetvers object; expected string values for windows, linux, and macos")
	}
	return windows, linux, macos, nil
}

func mergeGroupSettings(model *groupSettingsModel, raw map[string]any) {
	setIntSetting(raw, "auditmode", &model.AuditMode)
	setIntSetting(raw, "script_enabled", &model.ScriptControl)
	setIntSetting(raw, "cmdline_enabled", &model.CommandLineEnabled)
	setIntSetting(raw, "batch", &model.Batch)
	setIntSetting(raw, "powershell", &model.PowerShell)
	setIntSetting(raw, "command", &model.Command)
	setIntSetting(raw, "vbscript", &model.VBScript)
	setIntSetting(raw, "javascript", &model.JavaScript)
	setIntSetting(raw, "windowsinstaller", &model.WindowsInstaller)
	setIntSettingAliases(raw, []string{"htmlapplication", "htmlapplications"}, &model.HTMLApplications)
	setIntSettingAliases(raw, []string{"javaapplication", "javaapplications"}, &model.JavaApplications)
	setIntSetting(raw, "windowsscriptcomponent", &model.WindowsScriptComponent)
	setIntSetting(raw, "compiledhtml", &model.CompiledHTML)
	setIntSetting(raw, "shellscript", &model.ShellScript)
	setIntSetting(raw, "dylib", &model.Dylib)
	setIntSetting(raw, "python", &model.Python)
	setIntSetting(raw, "scpt", &model.SCPT)
	setIntSetting(raw, "script_custom", &model.ScriptCustom)
	setIntSetting(raw, "modreload", &model.ModuleReload)
	setIntSetting(raw, "poll_time", &model.PollTime)
	setIntSetting(raw, "pslockdown", &model.PowerShellLockdown)
	setIntSetting(raw, "proxyenabled", &model.ProxyEnabled)
	setStringSetting(raw, "proxyserver", &model.ProxyServer)
	setStringSetting(raw, "proxyport", &model.ProxyPort)
	setIntSetting(raw, "proxyauth", &model.ProxyAuthentication)
	setStringSetting(raw, "proxyuser", &model.ProxyUsername)
	setIntSetting(raw, "enable_notifications", &model.NotificationsEnabled)
	setStringSetting(raw, "notification_message", &model.NotificationMessage)
	setIntSetting(raw, "generalisation", &model.Generalisation)
	setIntSetting(raw, "browser", &model.Browser)
	setIntSetting(raw, "mactrustedinstaller", &model.MacTrustedInstaller)
	setIntSetting(raw, "mitrustedinstaller", &model.MicrosoftTrustedInstaller)
	setIntSetting(raw, "trusted_upload", &model.TrustedUpload)
	setBoolSetting(raw, "trusted_config", &model.TrustedConfig)
	setIntSetting(raw, "selfservice", &model.SelfService)
	setListSetting(raw, "custom_otp", &model.CustomOTP)
	setIntSetting(raw, "selfupgrade", &model.SelfUpgrade)
	setStringSetting(raw, "windows", &model.WindowsAgentVersion)
	setStringSetting(raw, "linux", &model.LinuxAgentVersion)
	setStringSetting(raw, "macos", &model.MacOSAgentVersion)
	if targetVersions, ok := firstMapValue(raw["targetvers"]); ok {
		setStringSetting(targetVersions, "windows", &model.WindowsAgentVersion)
		setStringSetting(targetVersions, "linux", &model.LinuxAgentVersion)
		setStringSetting(targetVersions, "macos", &model.MacOSAgentVersion)
	}
	setIntSetting(raw, "reflection", &model.Reflection)
	setStringSetting(raw, "commlistid", &model.CommunicationListID)
}

func zeroGroupSettingsModel(groupID string) groupSettingsModel {
	zeroInt := types.Int64Value(0)
	emptyString := types.StringValue("")
	return groupSettingsModel{
		ID: types.StringValue(groupID), GroupID: types.StringValue(groupID),
		AuditMode: zeroInt, ScriptControl: zeroInt, CommandLineEnabled: zeroInt,
		Batch: zeroInt, PowerShell: zeroInt, Command: zeroInt, VBScript: zeroInt,
		JavaScript: zeroInt, WindowsInstaller: zeroInt, HTMLApplications: zeroInt,
		JavaApplications: zeroInt, WindowsScriptComponent: zeroInt, CompiledHTML: zeroInt,
		ShellScript: zeroInt, Dylib: zeroInt, Python: zeroInt, SCPT: zeroInt,
		ScriptCustom: zeroInt, ModuleReload: zeroInt, PollTime: zeroInt,
		PowerShellLockdown: zeroInt, ProxyEnabled: zeroInt, ProxyServer: emptyString,
		ProxyPort: emptyString, ProxyAuthentication: zeroInt, ProxyUsername: emptyString,
		ProxyPasswordWO: types.StringNull(), ProxyPasswordWOVersion: zeroInt,
		NotificationsEnabled: zeroInt, NotificationMessage: emptyString,
		AgentStopCodeWO: types.StringNull(), AgentStopCodeWOVersion: zeroInt,
		Generalisation: zeroInt, Browser: zeroInt, MacTrustedInstaller: zeroInt,
		MicrosoftTrustedInstaller: zeroInt, TrustedUpload: zeroInt,
		TrustedConfig: types.BoolValue(false), SelfService: zeroInt,
		CustomOTP: types.ListValueMust(types.StringType, []attr.Value{}), SelfUpgrade: zeroInt,
		WindowsAgentVersion: emptyString, LinuxAgentVersion: emptyString,
		MacOSAgentVersion: emptyString, Reflection: zeroInt, CommunicationListID: emptyString,
	}
}

func setIntSetting(raw map[string]any, key string, target *types.Int64) {
	if value, ok := int64Value(raw[key]); ok {
		*target = types.Int64Value(value)
	}
}

func setIntSettingAliases(raw map[string]any, keys []string, target *types.Int64) {
	for _, key := range keys {
		if value, ok := int64Value(raw[key]); ok {
			*target = types.Int64Value(value)
			return
		}
	}
}

func setStringSetting(raw map[string]any, key string, target *types.String) {
	if value, ok := stringValue(raw[key]); ok {
		*target = types.StringValue(value)
	}
}

func setBoolSetting(raw map[string]any, key string, target *types.Bool) {
	if value, ok := boolValue(raw[key]); ok {
		*target = types.BoolValue(value)
	}
}

func setListSetting(raw map[string]any, key string, target *types.List) {
	values, ok := stringSliceValue(raw[key])
	if !ok {
		return
	}
	elements := make([]attr.Value, 0, len(values))
	for _, value := range values {
		elements = append(elements, types.StringValue(value))
	}
	*target = types.ListValueMust(types.StringType, elements)
}

func mapValue(value any) (map[string]any, bool) {
	switch value := value.(type) {
	case map[string]any:
		return value, true
	case json.RawMessage:
		var out map[string]any
		if json.Unmarshal(value, &out) == nil && out != nil {
			return out, true
		}
	case string:
		var out map[string]any
		if json.Unmarshal([]byte(value), &out) == nil && out != nil {
			return out, true
		}
	}
	return nil, false
}

func firstMapValue(value any) (map[string]any, bool) {
	if out, ok := mapValue(value); ok {
		return out, true
	}
	switch value := value.(type) {
	case []any:
		if len(value) != 0 {
			return mapValue(value[0])
		}
	case []map[string]any:
		if len(value) != 0 {
			return value[0], true
		}
	case json.RawMessage:
		var out []map[string]any
		if json.Unmarshal(value, &out) == nil && len(out) != 0 {
			return out[0], true
		}
	case string:
		var out []map[string]any
		if json.Unmarshal([]byte(value), &out) == nil && len(out) != 0 {
			return out[0], true
		}
	}
	return nil, false
}

func int64Value(value any) (int64, bool) {
	switch value := value.(type) {
	case int:
		return int64(value), true
	case int64:
		return value, true
	case float64:
		return int64(value), true
	case json.Number:
		out, err := value.Int64()
		return out, err == nil
	case bool:
		if value {
			return 1, true
		}
		return 0, true
	case string:
		out, err := strconv.ParseInt(strings.TrimSpace(value), 10, 64)
		return out, err == nil
	default:
		return 0, false
	}
}

func stringValue(value any) (string, bool) {
	switch value := value.(type) {
	case string:
		return value, true
	case json.Number:
		return value.String(), true
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64), true
	case int64:
		return strconv.FormatInt(value, 10), true
	case int:
		return strconv.Itoa(value), true
	default:
		return "", false
	}
}

func boolValue(value any) (bool, bool) {
	switch value := value.(type) {
	case bool:
		return value, true
	case string:
		out, err := strconv.ParseBool(strings.TrimSpace(value))
		if err == nil {
			return out, true
		}
		intValue, ok := int64Value(value)
		return intValue != 0, ok
	default:
		intValue, ok := int64Value(value)
		return intValue != 0, ok
	}
}

func stringSliceValue(value any) ([]string, bool) {
	switch value := value.(type) {
	case []string:
		return value, true
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			stringItem, ok := stringValue(item)
			if !ok {
				return nil, false
			}
			out = append(out, stringItem)
		}
		return out, true
	case string:
		var out []string
		if json.Unmarshal([]byte(value), &out) == nil {
			return out, true
		}
		return nil, false
	case nil:
		return []string{}, true
	default:
		return nil, false
	}
}

func stringsFromList(list types.List) []string {
	if list.IsNull() || list.IsUnknown() {
		return []string{}
	}
	out := make([]string, 0, len(list.Elements()))
	for _, element := range list.Elements() {
		value, ok := element.(types.String)
		if ok && !value.IsNull() && !value.IsUnknown() {
			out = append(out, value.ValueString())
		}
	}
	return out
}
