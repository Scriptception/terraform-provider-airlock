package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

func TestGroupSettingsSchemaUsesWriteOnlySecrets(t *testing.T) {
	attrs := groupSettingsSchema().Attributes
	for _, name := range []string{"proxy_password_wo", "agent_stop_code_wo"} {
		attribute, ok := attrs[name].(schema.StringAttribute)
		if !ok {
			t.Fatalf("%s has type %T, want schema.StringAttribute", name, attrs[name])
		}
		if !attribute.WriteOnly || !attribute.Sensitive || !attribute.Optional || attribute.Computed {
			t.Fatalf("%s is not optional sensitive write-only: %#v", name, attribute)
		}
	}
	if got := groupSettingsSchema().Version; got != 1 {
		t.Fatalf("schema version = %d, want 1", got)
	}
	pollTime, ok := attrs["poll_time"].(schema.Int64Attribute)
	if !ok || len(pollTime.Validators) != 1 {
		t.Fatalf("poll_time has unexpected schema: %#v", attrs["poll_time"])
	}
	if _, ok := pollTime.Validators[0].(nonNegativeInt64Validator); !ok {
		t.Fatalf("poll_time validator = %T, want nonNegativeInt64Validator", pollTime.Validators[0])
	}
}

func TestGroupSettingsReadMapping(t *testing.T) {
	model := zeroGroupSettingsModel("group-1")
	raw := map[string]any{
		"auditmode": 1, "script_enabled": 2, "cmdline_enabled": 1,
		"htmlapplication": 1, "javaapplication": 2,
		"custom_otp":          []any{"first", "second"},
		"mactrustedinstaller": 1, "mitrustedinstaller": 2,
		"modreload": 1, "scpt": 1, "script_custom": 2, "selfservice": 1,
		"trusted_config": true,
		"targetvers":     []any{map[string]any{"windows": "6.1.4.1", "linux": "6.1.4.2", "macos": "6.1.4.3"}},
		"applications":   []any{map[string]any{"applicationid": "not-a-setting"}},
	}
	mergeGroupSettings(&model, raw)

	if model.ScriptControl.ValueInt64() != 2 || model.CommandLineEnabled.ValueInt64() != 1 {
		t.Fatalf("script mappings were not applied: %#v", model)
	}
	if got := stringsFromList(model.CustomOTP); len(got) != 2 || got[0] != "first" || got[1] != "second" {
		t.Fatalf("custom_otp order changed: %#v", got)
	}
	if model.WindowsAgentVersion.ValueString() != "6.1.4.1" || model.MacOSAgentVersion.ValueString() != "6.1.4.3" {
		t.Fatalf("targetvers mapping failed: %#v", model)
	}

}

func TestParseLiveGroupSettingsRequiresCompleteDurableShape(t *testing.T) {
	model := zeroGroupSettingsModel("group-1")
	model.WindowsAgentVersion = types.StringValue("6.1.4.1")
	model.LinuxAgentVersion = types.StringValue("6.1.4.2")
	model.MacOSAgentVersion = types.StringValue("6.1.4.3")
	raw := completeLiveGroupSettings(model)
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatal(err)
	}

	got, err := parseLiveGroupSettings("group-1", decoded)
	if err != nil {
		t.Fatalf("parse complete response: %v", err)
	}
	if got.WindowsAgentVersion.ValueString() != "6.1.4.1" || got.LinuxAgentVersion.ValueString() != "6.1.4.2" || got.MacOSAgentVersion.ValueString() != "6.1.4.3" {
		t.Fatalf("target versions were not parsed: %#v", got)
	}

	delete(raw, "script_enabled")
	if _, err := parseLiveGroupSettings("group-1", raw); err == nil {
		t.Fatal("missing durable setting was accepted")
	}
}

func TestParseLiveGroupSettingsAcceptsProvenNullTargetVersions(t *testing.T) {
	raw := completeLiveGroupSettings(zeroGroupSettingsModel("group-1"))
	raw["targetvers"] = nil

	got, err := parseLiveGroupSettings("group-1", raw)
	if err != nil {
		t.Fatalf("parse null targetvers: %v", err)
	}
	if got.WindowsAgentVersion.ValueString() != "" || got.LinuxAgentVersion.ValueString() != "" || got.MacOSAgentVersion.ValueString() != "" {
		t.Fatalf("null targetvers did not map to empty versions: %#v", got)
	}
}

func TestParseLiveGroupSettingsRejectsUnprovenTargetVersionShapes(t *testing.T) {
	tests := map[string]any{
		"object":     map[string]any{"windows": "", "linux": "", "macos": ""},
		"empty list": []any{},
		"two entries": []any{
			map[string]any{"windows": "", "linux": "", "macos": ""},
			map[string]any{"windows": "", "linux": "", "macos": ""},
		},
		"missing key": []any{map[string]any{"windows": "", "linux": ""}},
		"extra key":   []any{map[string]any{"windows": "", "linux": "", "macos": "", "other": ""}},
	}
	for name, targetVersions := range tests {
		t.Run(name, func(t *testing.T) {
			raw := completeLiveGroupSettings(zeroGroupSettingsModel("group-1"))
			raw["targetvers"] = targetVersions
			if _, err := parseLiveGroupSettings("group-1", raw); err == nil {
				t.Fatalf("accepted targetvers: %#v", targetVersions)
			}
		})
	}
}

func TestGroupSettingsReconcileNoOpMakesNoWrites(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		writes++
		t.Fatalf("unexpected write to %s", req.URL.Path)
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}

	live := zeroGroupSettingsModel("group-1")
	plan := live
	prior := live
	resourceImpl := &groupSettingsResource{configuredResource: configuredResource{client: apiClient}}
	if err := resourceImpl.reconcileGroupSettings(context.Background(), live, plan, zeroGroupSettingsModel("group-1"), &prior); err != nil {
		t.Fatalf("no-op reconciliation: %v", err)
	}
	if writes != 0 {
		t.Fatalf("no-op reconciliation made %d writes", writes)
	}
}

func TestGroupSettingsReconcileRejectsUnsupportedChangeBeforeWrite(t *testing.T) {
	writes := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		writes++
		_, _ = w.Write([]byte(`{"error":"Success"}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}

	live := zeroGroupSettingsModel("group-1")
	plan := live
	plan.AuditMode = types.Int64Value(1)
	plan.CommandLineEnabled = types.Int64Value(1)
	resourceImpl := &groupSettingsResource{configuredResource: configuredResource{client: apiClient}}
	err = resourceImpl.reconcileGroupSettings(context.Background(), live, plan, zeroGroupSettingsModel("group-1"), nil)
	if err == nil || !strings.Contains(err.Error(), "command_line_enabled") {
		t.Fatalf("unsupported difference was not reported: %v", err)
	}
	if writes != 0 {
		t.Fatalf("unsupported difference allowed %d writes", writes)
	}
}

func TestGroupSettingsReconcileUsesOnlyChangedGranularEndpoints(t *testing.T) {
	paths := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		paths = append(paths, req.URL.Path)
		_, _ = w.Write([]byte(`{"error":"Success"}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}

	live := zeroGroupSettingsModel("group-1")
	plan := live
	plan.AuditMode = types.Int64Value(1)
	plan.NotificationsEnabled = types.Int64Value(1)
	plan.NotificationMessage = types.StringValue("Blocked by policy")
	plan.CommunicationListID = types.StringValue("list-1")
	plan.Reflection = types.Int64Value(1)
	plan.PowerShellLockdown = types.Int64Value(2)
	plan.PollTime = types.Int64Value(300)
	plan.ScriptControl = types.Int64Value(2)
	plan.ProxyServer = types.StringValue("proxy.example")
	plan.ProxyPort = types.StringValue("8080")
	plan.ProxyEnabled = types.Int64Value(1)
	prior := live
	resourceImpl := &groupSettingsResource{configuredResource: configuredResource{client: apiClient}}
	if err := resourceImpl.reconcileGroupSettings(context.Background(), live, plan, zeroGroupSettingsModel("group-1"), &prior); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"/v1/group/settings/auditmode",
		"/v1/group/settings/enable_notifications",
		"/v1/group/settings/notification_message",
		"/v1/group/settings/commlist",
		"/v1/group/settings/reflection",
		"/v1/group/settings/pslockdown",
		"/v1/group/settings/polltime",
		"/v1/group/settings/script",
		"/v1/group/settings/proxy/settings",
		"/v1/group/settings/proxy",
	}
	if strings.Join(paths, "\n") != strings.Join(want, "\n") {
		t.Fatalf("paths = %#v, want %#v", paths, want)
	}
}

func TestGroupSettingsReconcileRequiresProxyPasswordBeforeWrite(t *testing.T) {
	tests := map[string]func(*groupSettingsModel, *groupSettingsModel){
		"authenticated details change": func(live, plan *groupSettingsModel) {
			live.ProxyAuthentication = types.Int64Value(1)
			plan.ProxyAuthentication = types.Int64Value(1)
			plan.ProxyServer = types.StringValue("proxy.example")
		},
		"password version change": func(live, plan *groupSettingsModel) {
			live.ProxyAuthentication = types.Int64Value(1)
			plan.ProxyAuthentication = types.Int64Value(1)
			plan.ProxyPasswordWOVersion = types.Int64Value(1)
		},
		"password version change with authentication disabled": func(_, plan *groupSettingsModel) {
			plan.ProxyPasswordWOVersion = types.Int64Value(1)
		},
	}
	for name, change := range tests {
		t.Run(name, func(t *testing.T) {
			writes := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				writes++
				_, _ = w.Write([]byte(`{"error":"Success"}`))
			}))
			defer server.Close()
			apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
			if err != nil {
				t.Fatal(err)
			}

			live := zeroGroupSettingsModel("group-1")
			plan := live
			change(&live, &plan)
			prior := live
			prior.ProxyPasswordWOVersion = types.Int64Value(0)
			resourceImpl := &groupSettingsResource{configuredResource: configuredResource{client: apiClient}}
			err = resourceImpl.reconcileGroupSettings(context.Background(), live, plan, zeroGroupSettingsModel("group-1"), &prior)
			if err == nil || !strings.Contains(err.Error(), "proxy_password_wo") {
				t.Fatalf("missing proxy password was not reported: %v", err)
			}
			if writes != 0 {
				t.Fatalf("missing proxy password allowed %d writes", writes)
			}
		})
	}
}

func TestGroupSettingsReconcileProxyPasswordVersionUsesProxySettingsOnly(t *testing.T) {
	paths := make([]string, 0)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		paths = append(paths, req.URL.Path)
		if got := req.URL.Query().Get("password"); got != "test-proxy-password" {
			t.Fatalf("proxy password was not sent")
		}
		_, _ = w.Write([]byte(`{"error":"Success"}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}

	live := zeroGroupSettingsModel("group-1")
	live.ProxyAuthentication = types.Int64Value(1)
	live.ProxyServer = types.StringValue("proxy.example")
	live.ProxyPort = types.StringValue("8080")
	plan := live
	plan.ProxyPasswordWOVersion = types.Int64Value(1)
	prior := live
	config := zeroGroupSettingsModel("group-1")
	config.ProxyPasswordWO = types.StringValue("test-proxy-password")
	resourceImpl := &groupSettingsResource{configuredResource: configuredResource{client: apiClient}}
	if err := resourceImpl.reconcileGroupSettings(context.Background(), live, plan, config, &prior); err != nil {
		t.Fatal(err)
	}
	if len(paths) != 1 || paths[0] != "/v1/group/settings/proxy/settings" {
		t.Fatalf("paths = %#v, want only proxy/settings", paths)
	}
}

func completeLiveGroupSettings(model groupSettingsModel) map[string]any {
	return map[string]any{
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

func TestGroupSettingsStateUpgradeFromJSON(t *testing.T) {
	ctx := context.Background()
	prior := groupSettingsModelV0{
		ID:      types.StringValue("group-1"),
		GroupID: types.StringValue("group-1"),
		SettingsJSON: types.StringValue(`{
			"script_enabled":1,
			"poll_time":300,
			"proxypass":"must-not-enter-new-state",
			"agentstopcode":"must-not-enter-new-state",
			"custom_otp":["one","two"],
			"targetvers":[{"windows":"6.1.4.1","linux":"6.1.4.2","macos":"6.1.4.3"}]
		}`),
		PolicyJSON: types.StringValue(`{"applications":[{"applicationid":"ignored"}]}`),
	}
	priorState := tfsdk.State{Schema: groupSettingsSchemaV0()}
	if diags := priorState.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set prior state: %v", diags)
	}

	upgrader := (&groupSettingsResource{}).UpgradeState(ctx)[0]
	upgradeResp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: groupSettingsSchema()}}
	upgrader.StateUpgrader(ctx, resource.UpgradeStateRequest{State: &priorState}, upgradeResp)
	if upgradeResp.Diagnostics.HasError() {
		t.Fatalf("upgrade diagnostics: %v", upgradeResp.Diagnostics)
	}
	var got groupSettingsModel
	if diags := upgradeResp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("get upgraded state: %v", diags)
	}
	if got.ScriptControl.ValueInt64() != 1 || got.PollTime.ValueInt64() != 300 {
		t.Fatalf("durable settings were not migrated: %#v", got)
	}
	if !got.ProxyPasswordWO.IsNull() || !got.AgentStopCodeWO.IsNull() {
		t.Fatal("write-only secrets entered upgraded state")
	}
	if got.ProxyPasswordWOVersion.ValueInt64() != 0 || got.AgentStopCodeWOVersion.ValueInt64() != 0 {
		t.Fatal("secret version triggers did not start at zero")
	}
	if got.WindowsAgentVersion.ValueString() != "6.1.4.1" {
		t.Fatalf("targetvers was not migrated: %#v", got)
	}
}

func TestGroupSettingsStateUpgradeLegacyJSONValidation(t *testing.T) {
	tests := map[string]struct {
		settingsJSON types.String
		wantError    bool
	}{
		"null":       {settingsJSON: types.StringNull()},
		"empty":      {settingsJSON: types.StringValue("")},
		"whitespace": {settingsJSON: types.StringValue(" \n\t")},
		"object":     {settingsJSON: types.StringValue(`{"poll_time":300}`)},
		"malformed":  {settingsJSON: types.StringValue("{"), wantError: true},
		"array":      {settingsJSON: types.StringValue(`[]`), wantError: true},
		"JSON null":  {settingsJSON: types.StringValue(`null`), wantError: true},
		"unknown":    {settingsJSON: types.StringUnknown(), wantError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			prior := groupSettingsModelV0{
				ID:           types.StringValue("group-1"),
				GroupID:      types.StringValue("group-1"),
				SettingsJSON: test.settingsJSON,
				PolicyJSON:   types.StringValue(`{}`),
			}
			priorState := tfsdk.State{Schema: groupSettingsSchemaV0()}
			if diags := priorState.Set(ctx, &prior); diags.HasError() {
				t.Fatalf("set prior state: %v", diags)
			}

			upgrader := (&groupSettingsResource{}).UpgradeState(ctx)[0]
			upgradeResp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: groupSettingsSchema()}}
			upgrader.StateUpgrader(ctx, resource.UpgradeStateRequest{State: &priorState}, upgradeResp)
			if test.wantError {
				if !upgradeResp.Diagnostics.HasError() {
					t.Fatal("state upgrade accepted invalid legacy settings_json")
				}
				return
			}
			if upgradeResp.Diagnostics.HasError() {
				t.Fatalf("upgrade diagnostics: %v", upgradeResp.Diagnostics)
			}

			var got groupSettingsModel
			if diags := upgradeResp.State.Get(ctx, &got); diags.HasError() {
				t.Fatalf("get upgraded state: %v", diags)
			}
			if got.ID.ValueString() != "group-1" || got.GroupID.ValueString() != "group-1" {
				t.Fatalf("resource identity was not preserved: %#v", got)
			}
			if name == "object" && got.PollTime.ValueInt64() != 300 {
				t.Fatalf("non-empty settings_json was not migrated: %#v", got)
			}
			if !got.ProxyPasswordWO.IsNull() || !got.AgentStopCodeWO.IsNull() {
				t.Fatal("write-only secrets entered upgraded state")
			}
		})
	}
}
