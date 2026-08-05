package provider

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCanonicalMetaruleCriteriaStripsServerFields(t *testing.T) {
	raw := []byte(`[
		{"criteriaid":"server-1","index":0,"field":"publisher","operation":"match","value":"Publisher"},
		{"criteriaid":"server-2","index":1,"metaruleid":"rule-1","field":"path","operation":"wildcard","value":"C:\\Tools\\*"}
	]`)
	criteria, canonical, err := canonicalMetaruleCriteria(raw)
	if err != nil {
		t.Fatal(err)
	}
	if len(criteria) != 2 || criteria[0].Field != "publisher" || criteria[1].Field != "path" {
		t.Fatalf("criteria order changed: %#v", criteria)
	}
	for _, forbidden := range []string{"criteriaid", "metaruleid", "index", "server-1", "server-2"} {
		if strings.Contains(canonical, forbidden) {
			t.Fatalf("canonical criteria retained %q: %s", forbidden, canonical)
		}
	}
}

func TestMetaruleStateUpgradeUsesTypedCriteria(t *testing.T) {
	ctx := context.Background()
	prior := metaruleModelV0{
		ID:           types.StringValue("rule-1"),
		PackageID:    types.StringValue("package-1"),
		Name:         types.StringValue("Example"),
		OS:           types.StringValue("windows"),
		CriteriaJSON: types.StringValue(`[{"criteriaid":"server-1","field":"publisher","operation":"match","value":"Publisher"}]`),
		SettingsJSON: types.StringValue(`{"upload":1}`),
	}
	resourceImpl := &metaruleResource{kind: applicationMetarule}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	priorSchema := resourceImpl.UpgradeState(ctx)[0].PriorSchema
	priorState := tfsdk.State{Schema: *priorSchema}
	if diags := priorState.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set prior state: %v", diags)
	}

	upgradeResp := &resource.UpgradeStateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	resourceImpl.UpgradeState(ctx)[0].StateUpgrader(ctx, resource.UpgradeStateRequest{State: &priorState}, upgradeResp)
	if upgradeResp.Diagnostics.HasError() {
		t.Fatalf("upgrade diagnostics: %v", upgradeResp.Diagnostics)
	}
	var got metaruleModel
	if diags := upgradeResp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("get upgraded state: %v", diags)
	}
	if !got.CriteriaJSON.IsNull() {
		t.Fatalf("legacy criteria_json remained in upgraded state: %#v", got.CriteriaJSON)
	}
	if got.Criteria.IsNull() || got.Criteria.IsUnknown() || len(got.Criteria.Elements()) != 1 {
		t.Fatalf("typed criteria missing after upgrade: %#v", got.Criteria)
	}
	object, ok := got.Criteria.Elements()[0].(types.Object)
	if !ok || object.Attributes()["field"].(types.String).ValueString() != "publisher" {
		t.Fatalf("unexpected typed criteria: %#v", got.Criteria)
	}
	plan := tfsdk.Plan{Schema: schemaResp.Schema, Raw: upgradeResp.State.Raw}
	var planned metaruleModel
	if diags := plan.Get(ctx, &planned); diags.HasError() {
		t.Fatalf("decode upgraded plan: %v", diags)
	}
	criteria, err := metaruleCriteriaFromModel(ctx, planned)
	if err != nil || len(criteria) != 1 {
		t.Fatalf("upgraded typed plan is not usable: criteria=%#v err=%v", criteria, err)
	}
}

func TestMetaruleRejectsTypedAndJSONCriteriaTogether(t *testing.T) {
	model := metaruleModel{
		Criteria:     criteriaListValue([]metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Publisher"}}),
		CriteriaJSON: types.StringValue(`[{"field":"publisher","operation":"match","value":"Publisher"}]`),
	}
	if _, err := metaruleCriteriaFromModel(context.Background(), model); err == nil {
		t.Fatal("expected mixed criteria forms to be rejected")
	}
}

func TestMetaruleLegacyJSONConfigurationRemainsStable(t *testing.T) {
	configured := `[
		{"field":"publisher","operation":"match","value":"Publisher"}
	]`
	model := metaruleModel{
		Criteria:     types.ListNull(metaruleCriterionObjectType),
		CriteriaJSON: types.StringValue(configured),
	}
	if err := canonicaliseMetaruleModel(&model); err != nil {
		t.Fatal(err)
	}
	if model.CriteriaJSON.ValueString() != configured {
		t.Fatalf("configured criteria_json changed from %q to %q", configured, model.CriteriaJSON.ValueString())
	}
	if !model.Criteria.IsNull() {
		t.Fatalf("legacy JSON configuration retained a second criteria representation: %#v", model.Criteria)
	}
}

func TestMetaruleCriteriaFrameworkPlanRepresentations(t *testing.T) {
	ctx := context.Background()
	resourceImpl := &metaruleResource{kind: applicationMetarule}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	criteriaAttribute, ok := schemaResp.Schema.Attributes["criteria"].(schema.ListNestedAttribute)
	if !ok {
		t.Fatalf("criteria has type %T", schemaResp.Schema.Attributes["criteria"])
	}
	typedCriteria := criteriaListValue([]metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Publisher"}})
	legacyJSON := types.StringValue(`[{"field":"publisher","operation":"match","value":"Publisher"}]`)

	tests := []struct {
		name           string
		configCriteria types.List
		configJSON     types.String
		planCriteria   types.List
		wantNull       bool
		wantError      bool
	}{
		{name: "typed", configCriteria: typedCriteria, configJSON: types.StringNull(), planCriteria: typedCriteria},
		{name: "legacy JSON", configCriteria: types.ListNull(metaruleCriterionObjectType), configJSON: legacyJSON, planCriteria: types.ListUnknown(metaruleCriterionObjectType), wantNull: true},
		{name: "conflict", configCriteria: typedCriteria, configJSON: legacyJSON, planCriteria: typedCriteria, wantError: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configModel := metarulePlanTestModel(test.configCriteria, test.configJSON)
			stateModel := metarulePlanTestModel(typedCriteria, types.StringNull())
			planModel := metarulePlanTestModel(test.planCriteria, test.configJSON)
			configState := tfsdk.State{Schema: schemaResp.Schema}
			state := tfsdk.State{Schema: schemaResp.Schema}
			plan := tfsdk.Plan{Schema: schemaResp.Schema}
			if diags := configState.Set(ctx, &configModel); diags.HasError() {
				t.Fatalf("set config: %v", diags)
			}
			config := tfsdk.Config{Schema: schemaResp.Schema, Raw: configState.Raw}
			if diags := state.Set(ctx, &stateModel); diags.HasError() {
				t.Fatalf("set state: %v", diags)
			}
			if diags := plan.Set(ctx, &planModel); diags.HasError() {
				t.Fatalf("set plan: %v", diags)
			}

			req := planmodifier.ListRequest{
				Path:        pathRoot("criteria"),
				Config:      config,
				ConfigValue: test.configCriteria,
				Plan:        plan,
				PlanValue:   test.planCriteria,
				State:       state,
				StateValue:  typedCriteria,
			}
			resp := &planmodifier.ListResponse{PlanValue: test.planCriteria}
			for _, modifier := range criteriaAttribute.PlanModifiers {
				req.PlanValue = resp.PlanValue
				modifier.PlanModifyList(ctx, req, resp)
				if resp.Diagnostics.HasError() {
					break
				}
			}
			if resp.Diagnostics.HasError() != test.wantError {
				t.Fatalf("diagnostics=%v wantError=%t", resp.Diagnostics, test.wantError)
			}
			if test.wantError {
				return
			}
			if resp.PlanValue.IsNull() != test.wantNull {
				t.Fatalf("plan criteria null=%t, want %t: %#v", resp.PlanValue.IsNull(), test.wantNull, resp.PlanValue)
			}
			plannedModel := planModel
			plannedModel.Criteria = resp.PlanValue
			criteria, err := metaruleCriteriaFromModel(ctx, plannedModel)
			if err != nil || len(criteria) != 1 {
				t.Fatalf("planned representation is not usable: criteria=%#v err=%v", criteria, err)
			}
		})
	}
}

func TestMetaruleAdoptsImportedSettingsWithoutMutationAndPreservesID(t *testing.T) {
	ctx := context.Background()
	resourceImpl := &metaruleResource{kind: applicationMetarule}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)
	typedCriteria := criteriaListValue([]metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Publisher"}})
	prior := metarulePlanTestModel(typedCriteria, types.StringNull())
	prior.SettingsJSON = types.StringNull()
	planModel := prior
	planModel.ID = types.StringUnknown()
	planModel.SettingsJSON = types.StringValue(`{"upload":1}`)
	state := tfsdk.State{Schema: schemaResp.Schema}
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set state: %v", diags)
	}
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("set plan: %v", diags)
	}

	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	resourceImpl.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("adopt settings: %v", resp.Diagnostics)
	}
	var got metaruleModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("read adopted state: %v", diags)
	}
	if got.ID.ValueString() != "rule-1" {
		t.Fatalf("id = %q, want rule-1", got.ID.ValueString())
	}
	if got.SettingsJSON.ValueString() != `{"upload":1}` {
		t.Fatalf("settings_json = %q", got.SettingsJSON.ValueString())
	}
}

func metarulePlanTestModel(criteria types.List, criteriaJSON types.String) metaruleModel {
	return metaruleModel{
		ID:           types.StringValue("rule-1"),
		PackageID:    types.StringValue("package-1"),
		Name:         types.StringValue("Example"),
		OS:           types.StringValue("windows"),
		Criteria:     criteria,
		CriteriaJSON: criteriaJSON,
		SettingsJSON: types.StringNull(),
	}
}
