package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestCreateOnlyMetadataSchemasAreImportSafe(t *testing.T) {
	tests := []struct {
		name      string
		resource  resource.Resource
		attribute string
	}{
		{name: "application category", resource: NewApplicationResource(), attribute: "category_id"},
		{name: "baseline reference", resource: NewBaselineResource(), attribute: "reference_name"},
		{name: "repository hash path", resource: NewRepositoryHashResource(), attribute: "path"},
		{name: "metarule settings", resource: NewApplicationMetaruleResource(), attribute: "settings_json"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resourceSchema := schemaForResourceTest(t, test.resource)
			attribute, ok := resourceSchema.Attributes[test.attribute].(schema.StringAttribute)
			if !ok {
				t.Fatalf("%s has type %T", test.attribute, resourceSchema.Attributes[test.attribute])
			}
			if !attribute.Optional || !attribute.Computed {
				t.Fatalf("%s must be Optional and Computed: %#v", test.attribute, attribute)
			}
			if requiresReplace := createOnlyMetadataRequiresReplace(t, attribute, types.StringNull(), types.StringValue("declared-after-import")); requiresReplace {
				t.Fatalf("%s requires replacement when adopting metadata after import", test.attribute)
			}
			if requiresReplace := createOnlyMetadataRequiresReplace(t, attribute, types.StringValue("original"), types.StringValue("changed")); !requiresReplace {
				t.Fatalf("%s did not require replacement after recorded metadata changed", test.attribute)
			}
		})
	}
}

func TestSimpleResourceAdoptsImportedCreateOnlyMetadataIntoState(t *testing.T) {
	ctx := context.Background()
	application := NewApplicationResource().(*simpleResource)
	resourceSchema := schemaForResourceTest(t, application)
	state := tfsdk.State{Schema: resourceSchema}
	plan := tfsdk.Plan{Schema: resourceSchema}

	type applicationState struct {
		ID         types.String `tfsdk:"id"`
		Name       types.String `tfsdk:"name"`
		Version    types.String `tfsdk:"version"`
		CategoryID types.String `tfsdk:"category_id"`
	}
	stateValues := applicationState{
		ID:         types.StringValue("application-1"),
		Name:       types.StringValue("Imported application"),
		Version:    types.StringValue("1"),
		CategoryID: types.StringNull(),
	}
	planValues := applicationState{
		ID:         types.StringUnknown(),
		Name:       types.StringValue("Imported application"),
		Version:    types.StringValue("1"),
		CategoryID: types.StringValue("category-1"),
	}
	if diags := state.Set(ctx, stateValues); diags.HasError() {
		t.Fatalf("set state: %v", diags)
	}
	if diags := plan.Set(ctx, planValues); diags.HasError() {
		t.Fatalf("set plan: %v", diags)
	}

	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: resourceSchema, Raw: plan.Raw}}
	application.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("adopt metadata: %v", resp.Diagnostics)
	}
	var got types.String
	if diags := resp.State.GetAttribute(ctx, pathRoot("category_id"), &got); diags.HasError() {
		t.Fatalf("read adopted state: %v", diags)
	}
	if got.ValueString() != "category-1" {
		t.Fatalf("category_id = %q, want category-1", got.ValueString())
	}
	if diags := resp.State.GetAttribute(ctx, pathRoot("id"), &got); diags.HasError() {
		t.Fatalf("read preserved id: %v", diags)
	}
	if got.ValueString() != "application-1" {
		t.Fatalf("id = %q, want application-1", got.ValueString())
	}
}

func schemaForResourceTest(t *testing.T, providerResource resource.Resource) schema.Schema {
	t.Helper()
	resp := &resource.SchemaResponse{}
	providerResource.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("resource schema: %v", resp.Diagnostics)
	}
	return resp.Schema
}

func createOnlyMetadataRequiresReplace(t *testing.T, attribute schema.StringAttribute, stateValue, planValue types.String) bool {
	t.Helper()
	ctx := context.Background()
	testSchema := schema.Schema{Attributes: map[string]schema.Attribute{"value": attribute}}
	state := tfsdk.State{Schema: testSchema}
	plan := tfsdk.Plan{Schema: testSchema}
	type testModel struct {
		Value types.String `tfsdk:"value"`
	}
	if diags := state.Set(ctx, &testModel{Value: stateValue}); diags.HasError() {
		t.Fatalf("set modifier state: %v", diags)
	}
	if diags := plan.Set(ctx, &testModel{Value: planValue}); diags.HasError() {
		t.Fatalf("set modifier plan: %v", diags)
	}

	req := planmodifier.StringRequest{
		ConfigValue: planValue,
		Plan:        plan,
		PlanValue:   planValue,
		State:       state,
		StateValue:  stateValue,
	}
	resp := &planmodifier.StringResponse{PlanValue: planValue}
	for _, modifier := range attribute.PlanModifiers {
		req.PlanValue = resp.PlanValue
		modifier.PlanModifyString(ctx, req, resp)
	}
	if resp.Diagnostics.HasError() {
		t.Fatalf("plan modifiers: %v", resp.Diagnostics)
	}
	return resp.RequiresReplace
}
