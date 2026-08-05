package provider

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
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

func TestGroupSettingsReadMappingAndPayload(t *testing.T) {
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

	payload := groupSettingsPayload(model)
	for key, want := range map[string]any{
		"groupid": "group-1", "script_enabled": int64(2), "cmdline_enabled": int64(1),
		"mactrustedinstaller": int64(1), "mitrustedinstaller": int64(2),
		"htmlapplication": int64(1), "javaapplication": int64(2),
		"modreload": int64(1), "scpt": int64(1), "script_custom": int64(2),
		"selfservice": int64(1), "trusted_config": true,
	} {
		if got := payload[key]; got != want {
			t.Fatalf("payload[%q] = %#v, want %#v", key, got, want)
		}
	}
	targetVersions, ok := payload["targetvers"].([]map[string]string)
	if !ok || len(targetVersions) != 1 || targetVersions[0]["windows"] != "6.1.4.1" || targetVersions[0]["linux"] != "6.1.4.2" || targetVersions[0]["macos"] != "6.1.4.3" {
		t.Fatalf("payload targetvers has unexpected shape: %#v", payload["targetvers"])
	}
	for _, excluded := range []string{"applications", "baselines", "blocklists", "paths", "publishers", "proxypass", "agentstopcode", "htmlapplications", "javaapplications", "windows", "linux", "macos"} {
		if _, ok := payload[excluded]; ok {
			t.Fatalf("payload unexpectedly contains %q", excluded)
		}
	}
}

func TestParseLiveGroupSettingsRequiresCompleteDurableShape(t *testing.T) {
	model := zeroGroupSettingsModel("group-1")
	model.WindowsAgentVersion = types.StringValue("6.1.4.1")
	model.LinuxAgentVersion = types.StringValue("6.1.4.2")
	model.MacOSAgentVersion = types.StringValue("6.1.4.3")
	raw := groupSettingsPayload(model)
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
	raw := groupSettingsPayload(zeroGroupSettingsModel("group-1"))
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
			raw := groupSettingsPayload(zeroGroupSettingsModel("group-1"))
			raw["targetvers"] = targetVersions
			if _, err := parseLiveGroupSettings("group-1", raw); err == nil {
				t.Fatalf("accepted targetvers: %#v", targetVersions)
			}
		})
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
