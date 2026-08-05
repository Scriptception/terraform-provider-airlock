package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/setplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

type configuredResource struct{ client *client.Client }

func (r *configuredResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", req.ProviderData))
		return
	}
	r.client = c
}

type metaruleKind string

const (
	applicationMetarule metaruleKind = "application"
	blocklistMetarule   metaruleKind = "blocklist"
)

type metaruleResource struct {
	configuredResource
	kind metaruleKind
}

type metaruleModel struct {
	ID           types.String `tfsdk:"id"`
	PackageID    types.String `tfsdk:"package_id"`
	Name         types.String `tfsdk:"name"`
	OS           types.String `tfsdk:"os"`
	Criteria     types.List   `tfsdk:"criteria"`
	CriteriaJSON types.String `tfsdk:"criteria_json"`
	SettingsJSON types.String `tfsdk:"settings_json"`
}

type metaruleModelV0 struct {
	ID           types.String `tfsdk:"id"`
	PackageID    types.String `tfsdk:"package_id"`
	Name         types.String `tfsdk:"name"`
	OS           types.String `tfsdk:"os"`
	CriteriaJSON types.String `tfsdk:"criteria_json"`
	SettingsJSON types.String `tfsdk:"settings_json"`
}

var metaruleCriterionAttributeTypes = map[string]attr.Type{
	"field":     types.StringType,
	"operation": types.StringType,
	"value":     types.StringType,
}

var metaruleCriterionObjectType = types.ObjectType{AttrTypes: metaruleCriterionAttributeTypes}

func NewApplicationMetaruleResource() resource.Resource {
	return &metaruleResource{kind: applicationMetarule}
}
func NewBlocklistMetaruleResource() resource.Resource {
	return &metaruleResource{kind: blocklistMetarule}
}
func (r *metaruleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + string(r.kind) + "_metarule"
}
func (r *metaruleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Version: 1, Description: "Manage an Airlock " + string(r.kind) + " metarule.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, Description: "Airlock metarule UUID."},
		"package_id": schema.StringAttribute{Required: true, Description: "Target Airlock package ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"name":       schema.StringAttribute{Required: true, Description: "Metarule name."},
		"os":         schema.StringAttribute{Required: true, Description: "Operating system: windows, linux, or mac.", Validators: []validator.String{stringOneOfValidator{allowed: []string{"windows", "linux", "mac"}}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"criteria": schema.ListNestedAttribute{
			Optional:    true,
			Computed:    true,
			Description: "Ordered list of 1-5 metarule criteria. Use this instead of criteria_json.",
			NestedObject: schema.NestedAttributeObject{Attributes: map[string]schema.Attribute{
				"field":     schema.StringAttribute{Required: true, Description: "Airlock criteria field."},
				"operation": schema.StringAttribute{Required: true, Description: "Airlock criteria operation."},
				"value":     schema.StringAttribute{Required: true, Description: "Value to match."},
			}},
			PlanModifiers: []planmodifier.List{metaruleCriteriaRepresentationModifier{}, listplanmodifier.UseStateForUnknown(), listplanmodifier.RequiresReplace()},
		},
		"criteria_json": schema.StringAttribute{Optional: true, Description: "Deprecated JSON form of criteria. New configurations should use criteria. Server criteria IDs and ordering metadata are removed during canonical readback.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"settings_json": optionalComputedCreateOnlyString("Deprecated create-time JSON settings. Airlock does not provide reliable settings readback for drift detection. An imported resource may adopt this value into state once without an API mutation; later changes replace the resource."),
	}}
}
func (r *metaruleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan metaruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, err := r.metaruleBody(ctx, plan)
	if err != nil {
		resp.Diagnostics.AddError("Invalid Airlock metarule", err.Error())
		return
	}
	if err := canonicaliseMetaruleModel(&plan); err != nil {
		resp.Diagnostics.AddError("Invalid Airlock metarule", err.Error())
		return
	}
	var id string
	if r.kind == applicationMetarule {
		id, err = r.client.CreateApplicationMetarule(ctx, body)
	} else {
		id, err = r.client.CreateBlocklistMetarule(ctx, body)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Airlock metarule", err.Error())
		return
	}
	if id == "" {
		resp.Diagnostics.AddError("Unable to create Airlock metarule", "The API did not return a metarule ID.")
		return
	}
	plan.ID = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *metaruleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state metaruleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	rules, err := r.listMetarules(ctx, state.PackageID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock metarule", err.Error())
		return
	}
	for _, rule := range rules {
		if rule.ID == state.ID.ValueString() {
			state.Name = types.StringValue(rule.Name)
			state.OS = types.StringValue(rule.OS)
			if len(rule.Criteria) > 0 && string(rule.Criteria) != "null" {
				criteria, _, err := canonicalMetaruleCriteria(rule.Criteria)
				if err != nil {
					resp.Diagnostics.AddError("Unable to read Airlock metarule criteria", err.Error())
					return
				}
				if state.CriteriaJSON.IsNull() || state.CriteriaJSON.IsUnknown() || strings.TrimSpace(state.CriteriaJSON.ValueString()) == "" {
					state.Criteria = criteriaListValue(criteria)
				} else {
					state.Criteria = types.ListNull(metaruleCriterionObjectType)
				}
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}
func (r *metaruleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan metaruleModel
	var prior metaruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	plan.ID = prior.ID
	settingsAdoption := createOnlyMetadataAdoption(prior.SettingsJSON, plan.SettingsJSON)
	if !settingsAdoption && !plan.SettingsJSON.Equal(prior.SettingsJSON) {
		resp.Diagnostics.AddError("Update not supported", "Changing recorded metarule settings_json requires replacement.")
		return
	}
	if settingsAdoption && plan.Name.Equal(prior.Name) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	if plan.Name.Equal(prior.Name) {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	var err error
	if r.kind == applicationMetarule {
		err = r.client.UpdateApplicationMetaruleName(ctx, prior.ID.ValueString(), plan.Name.ValueString())
	} else {
		err = r.client.UpdateBlocklistMetaruleName(ctx, prior.ID.ValueString(), plan.Name.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock metarule", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *metaruleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state metaruleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var err error
	if r.kind == applicationMetarule {
		err = r.client.DeleteApplicationMetarule(ctx, state.ID.ValueString())
	} else {
		err = r.client.DeleteBlocklistMetarule(ctx, state.ID.ValueString())
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to delete Airlock metarule", err.Error())
	}
}
func (r *metaruleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected package_id:metarule_id.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("package_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), parts[1])...)
}
func (r *metaruleResource) UpgradeState(_ context.Context) map[int64]resource.StateUpgrader {
	priorSchema := schema.Schema{Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true},
		"package_id":    schema.StringAttribute{Required: true},
		"name":          schema.StringAttribute{Required: true},
		"os":            schema.StringAttribute{Required: true},
		"criteria_json": schema.StringAttribute{Required: true},
		"settings_json": schema.StringAttribute{Optional: true, Computed: true},
	}}
	return map[int64]resource.StateUpgrader{
		0: {
			PriorSchema: &priorSchema,
			StateUpgrader: func(ctx context.Context, req resource.UpgradeStateRequest, resp *resource.UpgradeStateResponse) {
				var prior metaruleModelV0
				resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
				if resp.Diagnostics.HasError() {
					return
				}
				criteria, _, err := canonicalMetaruleCriteria([]byte(prior.CriteriaJSON.ValueString()))
				if err != nil {
					resp.Diagnostics.AddError("Unable to upgrade Airlock metarule state", err.Error())
					return
				}
				next := metaruleModel{
					ID: prior.ID, PackageID: prior.PackageID, Name: prior.Name, OS: prior.OS,
					Criteria: criteriaListValue(criteria), CriteriaJSON: types.StringNull(), SettingsJSON: prior.SettingsJSON,
				}
				resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
			},
		},
	}
}
func (r *metaruleResource) metaruleBody(ctx context.Context, m metaruleModel) (map[string]any, error) {
	criteria, err := metaruleCriteriaFromModel(ctx, m)
	if err != nil {
		return nil, err
	}
	body := map[string]any{"name": m.Name.ValueString(), "os": m.OS.ValueString(), "criteria": criteria}
	if r.kind == applicationMetarule {
		body["applicationid"] = m.PackageID.ValueString()
	} else {
		body["blocklistid"] = m.PackageID.ValueString()
	}
	if !m.SettingsJSON.IsNull() && !m.SettingsJSON.IsUnknown() && m.SettingsJSON.ValueString() != "" {
		settings, err := jsonObject(m.SettingsJSON.ValueString())
		if err != nil {
			return nil, fmt.Errorf("settings_json must be a valid JSON object: %w", err)
		}
		body["settings"] = settings
	}
	return body, nil
}
func (r *metaruleResource) listMetarules(ctx context.Context, packageID string) ([]client.Metarule, error) {
	if r.kind == applicationMetarule {
		return r.client.ListApplicationMetarules(ctx, packageID, true)
	}
	return r.client.ListBlocklistMetarules(ctx, packageID, true)
}

type metaruleCriterion struct {
	Field     string `json:"field"`
	Operation string `json:"operation"`
	Value     string `json:"value"`
}

func metaruleCriteriaFromModel(_ context.Context, model metaruleModel) ([]metaruleCriterion, error) {
	typedConfigured := !model.Criteria.IsNull() && !model.Criteria.IsUnknown() && len(model.Criteria.Elements()) > 0
	jsonConfigured := !model.CriteriaJSON.IsNull() && !model.CriteriaJSON.IsUnknown() && strings.TrimSpace(model.CriteriaJSON.ValueString()) != ""
	if typedConfigured && jsonConfigured {
		return nil, fmt.Errorf("criteria and criteria_json cannot both be configured")
	}
	if jsonConfigured {
		criteria, _, err := canonicalMetaruleCriteria([]byte(model.CriteriaJSON.ValueString()))
		return criteria, err
	}
	if !typedConfigured {
		return nil, fmt.Errorf("configure criteria or criteria_json")
	}
	criteria := make([]metaruleCriterion, 0, len(model.Criteria.Elements()))
	for i, element := range model.Criteria.Elements() {
		object, ok := element.(types.Object)
		if !ok || object.IsNull() || object.IsUnknown() {
			return nil, fmt.Errorf("criteria[%d] must be a known object", i)
		}
		values := object.Attributes()
		field, fieldOK := knownObjectString(values["field"])
		operation, operationOK := knownObjectString(values["operation"])
		value, valueOK := knownObjectString(values["value"])
		if !fieldOK || !operationOK || !valueOK {
			return nil, fmt.Errorf("criteria[%d] field, operation, and value must be known strings", i)
		}
		criteria = append(criteria, metaruleCriterion{Field: field, Operation: operation, Value: value})
	}
	return validateMetaruleCriteria(criteria)
}

func canonicalMetaruleCriteria(raw []byte) ([]metaruleCriterion, string, error) {
	var objects []map[string]any
	if err := json.Unmarshal(raw, &objects); err != nil {
		return nil, "", fmt.Errorf("criteria must be a JSON array: %w", err)
	}
	criteria := make([]metaruleCriterion, 0, len(objects))
	for i, object := range objects {
		field, fieldOK := stringValue(object["field"])
		operation, operationOK := stringValue(object["operation"])
		value, valueOK := stringValue(object["value"])
		if !fieldOK || !operationOK || !valueOK {
			return nil, "", fmt.Errorf("criteria[%d] must contain string field, operation, and value attributes", i)
		}
		criteria = append(criteria, metaruleCriterion{Field: field, Operation: operation, Value: value})
	}
	criteria, err := validateMetaruleCriteria(criteria)
	if err != nil {
		return nil, "", err
	}
	canonical, err := json.Marshal(criteria)
	if err != nil {
		return nil, "", fmt.Errorf("encode canonical criteria: %w", err)
	}
	return criteria, string(canonical), nil
}

func validateMetaruleCriteria(criteria []metaruleCriterion) ([]metaruleCriterion, error) {
	if len(criteria) < 1 || len(criteria) > 5 {
		return nil, fmt.Errorf("criteria must contain between 1 and 5 items")
	}
	for i, criterion := range criteria {
		if strings.TrimSpace(criterion.Field) == "" || strings.TrimSpace(criterion.Operation) == "" {
			return nil, fmt.Errorf("criteria[%d] field and operation must not be empty", i)
		}
	}
	return criteria, nil
}

func canonicaliseMetaruleModel(model *metaruleModel) error {
	criteria, err := metaruleCriteriaFromModel(context.Background(), *model)
	if err != nil {
		return err
	}
	if !model.CriteriaJSON.IsNull() && !model.CriteriaJSON.IsUnknown() && strings.TrimSpace(model.CriteriaJSON.ValueString()) != "" {
		model.Criteria = types.ListNull(metaruleCriterionObjectType)
	} else {
		model.Criteria = criteriaListValue(criteria)
	}
	return nil
}

type metaruleCriteriaRepresentationModifier struct{}

func (metaruleCriteriaRepresentationModifier) Description(context.Context) string {
	return "Keeps typed criteria and legacy criteria_json as mutually exclusive plan representations."
}

func (m metaruleCriteriaRepresentationModifier) MarkdownDescription(ctx context.Context) string {
	return m.Description(ctx)
}

func (metaruleCriteriaRepresentationModifier) PlanModifyList(ctx context.Context, req planmodifier.ListRequest, resp *planmodifier.ListResponse) {
	var criteriaJSON types.String
	resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("criteria_json"), &criteriaJSON)...)
	if resp.Diagnostics.HasError() || criteriaJSON.IsNull() || criteriaJSON.IsUnknown() || strings.TrimSpace(criteriaJSON.ValueString()) == "" {
		return
	}
	if !req.ConfigValue.IsNull() && !req.ConfigValue.IsUnknown() && len(req.ConfigValue.Elements()) > 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Conflicting metarule criteria", "Configure criteria or criteria_json, not both.")
		return
	}
	resp.PlanValue = types.ListNull(metaruleCriterionObjectType)
}

func criteriaListValue(criteria []metaruleCriterion) types.List {
	elements := make([]attr.Value, 0, len(criteria))
	for _, criterion := range criteria {
		elements = append(elements, types.ObjectValueMust(metaruleCriterionAttributeTypes, map[string]attr.Value{
			"field":     types.StringValue(criterion.Field),
			"operation": types.StringValue(criterion.Operation),
			"value":     types.StringValue(criterion.Value),
		}))
	}
	return types.ListValueMust(metaruleCriterionObjectType, elements)
}

func knownObjectString(value attr.Value) (string, bool) {
	stringValue, ok := value.(types.String)
	if !ok || stringValue.IsNull() || stringValue.IsUnknown() {
		return "", false
	}
	return stringValue.ValueString(), true
}

type hashMembershipResource struct {
	configuredResource
	kind string
}

type hashMembershipModel struct {
	ID       types.String `tfsdk:"id"`
	TargetID types.String `tfsdk:"target_id"`
	Hashes   types.Set    `tfsdk:"hashes"`
}

func NewRepositoryHashResource() resource.Resource { return &repositoryHashResource{} }
func NewApplicationHashResource() resource.Resource {
	return &hashMembershipResource{kind: "application"}
}
func NewBaselineHashResource() resource.Resource  { return &hashMembershipResource{kind: "baseline"} }
func NewBlocklistHashResource() resource.Resource { return &hashMembershipResource{kind: "blocklist"} }
func (r *hashMembershipResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.kind + "_hashes"
}
func (r *hashMembershipResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	hashAttribute := schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "SHA256 hashes."}
	description := "Manage additive SHA256 hash membership for an Airlock baseline package. Reference baseline content is not authoritative or managed by this resource."
	if r.authoritative() {
		description = "Authoritatively manage the complete SHA256 hash membership for one Airlock " + r.kind + " package. Configure only one resource per package."
		hashAttribute.Description = "Complete desired set of SHA256 hashes for the package."
	} else {
		hashAttribute.PlanModifiers = []planmodifier.Set{setplanmodifier.RequiresReplace()}
	}
	resp.Schema = schema.Schema{Description: "Manage SHA256 hash membership for an Airlock " + r.kind + " package.", Attributes: map[string]schema.Attribute{
		"id":        schema.StringAttribute{Computed: true, Description: "Stable Terraform ID."},
		"target_id": schema.StringAttribute{Required: true, Description: "Target Airlock package ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"hashes":    hashAttribute,
	}}
	resp.Schema.Description = description
}
func (r *hashMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hashMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hashes, err := normalizeHashes(stringsFromSet(ctx, plan.Hashes))
	if err != nil {
		resp.Diagnostics.AddAttributeError(pathRoot("hashes"), "Invalid SHA256 hash", err.Error())
		return
	}
	if r.authoritative() {
		err = r.reconcileHashes(ctx, plan.TargetID.ValueString(), hashes)
	} else {
		err = r.addHashes(ctx, plan.TargetID.ValueString(), hashes)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to add Airlock hashes", err.Error())
		return
	}
	plan.ID = types.StringValue(r.membershipID(plan.TargetID.ValueString(), hashes))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *hashMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hashMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.authoritative() && legacyAuthoritativeHashMembership(r.kind, state.ID.ValueString()) {
		resp.Diagnostics.AddError("Legacy Airlock hash membership cannot be refreshed safely", legacyAuthoritativeHashMigrationGuidance(r.kind, state.TargetID.ValueString()))
		return
	}
	exported, err := r.exportedHashes(ctx, state.TargetID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to export Airlock "+r.kind+" hashes", err.Error())
		return
	}
	if r.authoritative() {
		hashSet, diags := types.SetValueFrom(ctx, types.StringType, exported)
		resp.Diagnostics.Append(diags...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Hashes = hashSet
		state.ID = types.StringValue(r.membershipID(state.TargetID.ValueString(), exported))
	} else {
		hashes, err := normalizeHashes(stringsFromSet(ctx, state.Hashes))
		if err != nil {
			resp.Diagnostics.AddAttributeError(pathRoot("hashes"), "Invalid SHA256 hash", err.Error())
			return
		}
		if !hashesSubset(exported, hashes) {
			resp.State.RemoveResource(ctx)
			return
		}
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *hashMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	if !r.authoritative() {
		resp.Diagnostics.AddError("Update not supported", "Baseline hash membership changes require replacement.")
		return
	}
	var plan hashMembershipModel
	var prior hashMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if legacyAuthoritativeHashMembership(r.kind, prior.ID.ValueString()) {
		resp.Diagnostics.AddError("Legacy Airlock hash membership cannot be updated safely", legacyAuthoritativeHashMigrationGuidance(r.kind, prior.TargetID.ValueString()))
		return
	}
	hashes, err := normalizeHashes(stringsFromSet(ctx, plan.Hashes))
	if err != nil {
		resp.Diagnostics.AddAttributeError(pathRoot("hashes"), "Invalid SHA256 hash", err.Error())
		return
	}
	if err := r.reconcileHashes(ctx, plan.TargetID.ValueString(), hashes); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock "+r.kind+" hashes", err.Error())
		return
	}
	plan.ID = types.StringValue(r.membershipID(plan.TargetID.ValueString(), hashes))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *hashMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hashMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.authoritative() && legacyAuthoritativeHashMembership(r.kind, state.ID.ValueString()) {
		resp.Diagnostics.AddError("Legacy Airlock hash membership cannot be destroyed safely", legacyAuthoritativeHashMigrationGuidance(r.kind, state.TargetID.ValueString()))
		return
	}
	var hashes []string
	var err error
	if r.authoritative() {
		hashes, err = r.exportedHashes(ctx, state.TargetID.ValueString())
	} else {
		hashes, err = normalizeHashes(stringsFromSet(ctx, state.Hashes))
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock hashes before removal", err.Error())
		return
	}
	if err := r.removeHashes(ctx, state.TargetID.ValueString(), hashes); err != nil {
		resp.Diagnostics.AddError("Unable to remove Airlock hashes", err.Error())
		return
	}
	if r.authoritative() {
		remaining, err := r.exportedHashes(ctx, state.TargetID.ValueString())
		if err != nil {
			resp.Diagnostics.AddError("Unable to verify Airlock hash removal", err.Error())
			return
		}
		if len(remaining) != 0 {
			resp.Diagnostics.AddError("Unable to verify Airlock hash removal", fmt.Sprintf("Airlock still reported %d hashes for the package after removal.", len(remaining)))
		}
	}
}
func (r *hashMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if r.authoritative() {
		if legacyAuthoritativeHashMembership(r.kind, req.ID) {
			parts := strings.SplitN(req.ID, ":", 3)
			resp.Diagnostics.AddError("Legacy Airlock hash membership import is not supported", legacyAuthoritativeHashMigrationGuidance(r.kind, parts[1]))
			return
		}
		targetID, err := parseAuthoritativeHashMembershipImportID(r.kind, req.ID)
		if err != nil {
			resp.Diagnostics.AddError("Invalid import ID", err.Error())
			return
		}
		emptySet, diags := types.SetValueFrom(ctx, types.StringType, []string{})
		resp.Diagnostics.Append(diags...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), r.membershipID(targetID, nil))...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("target_id"), targetID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("hashes"), emptySet)...)
		return
	}
	targetID, hashes, id, err := parseHashMembershipImportID(r.kind, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())
		return
	}
	hashSet, diags := types.SetValueFrom(ctx, types.StringType, hashes)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), id)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("target_id"), targetID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("hashes"), hashSet)...)
}

const hashMutationBatchSize = 250

func (r *hashMembershipResource) authoritative() bool {
	return r.kind == "application" || r.kind == "blocklist"
}

func (r *hashMembershipResource) membershipID(targetID string, hashes []string) string {
	if r.authoritative() {
		return r.kind + ":" + targetID
	}
	return hashMembershipID(r.kind, targetID, hashes)
}

func (r *hashMembershipResource) reconcileHashes(ctx context.Context, targetID string, desired []string) error {
	current, err := r.exportedHashes(ctx, targetID)
	if err != nil {
		return err
	}
	add, remove := hashSetDiff(current, desired)
	if err := r.addHashes(ctx, targetID, add); err != nil {
		return err
	}
	if err := r.removeHashes(ctx, targetID, remove); err != nil {
		return err
	}
	verified, err := r.exportedHashes(ctx, targetID)
	if err != nil {
		return fmt.Errorf("verify reconciled Airlock hashes: %w", err)
	}
	if !hashesSubset(verified, desired) || !hashesSubset(desired, verified) {
		return fmt.Errorf("Airlock package reported %d hashes after reconciliation; expected %d", len(verified), len(desired))
	}
	return nil
}

func (r *hashMembershipResource) addHashes(ctx context.Context, targetID string, hashes []string) error {
	for _, batch := range hashBatches(hashes, hashMutationBatchSize) {
		var err error
		switch r.kind {
		case "application":
			err = r.client.AddApplicationHash(ctx, targetID, batch)
		case "baseline":
			err = r.client.AddBaselineHash(ctx, targetID, batch)
		case "blocklist":
			err = r.client.AddBlocklistHash(ctx, targetID, batch)
		default:
			return fmt.Errorf("unsupported hash membership kind %q", r.kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func (r *hashMembershipResource) removeHashes(ctx context.Context, targetID string, hashes []string) error {
	for _, batch := range hashBatches(hashes, hashMutationBatchSize) {
		var err error
		switch r.kind {
		case "application":
			err = r.client.RemoveApplicationHash(ctx, targetID, batch)
		case "baseline":
			err = r.client.RemoveBaselineHash(ctx, targetID, batch)
		case "blocklist":
			err = r.client.RemoveBlocklistHash(ctx, targetID, batch)
		default:
			return fmt.Errorf("unsupported hash membership kind %q", r.kind)
		}
		if err != nil {
			return err
		}
	}
	return nil
}

func hashSetDiff(current, desired []string) (add, remove []string) {
	current, _ = normalizeHashes(current)
	desired, _ = normalizeHashes(desired)
	currentSet := make(map[string]struct{}, len(current))
	desiredSet := make(map[string]struct{}, len(desired))
	for _, hash := range current {
		currentSet[hash] = struct{}{}
	}
	for _, hash := range desired {
		desiredSet[hash] = struct{}{}
		if _, ok := currentSet[hash]; !ok {
			add = append(add, hash)
		}
	}
	for _, hash := range current {
		if _, ok := desiredSet[hash]; !ok {
			remove = append(remove, hash)
		}
	}
	return add, remove
}

func hashBatches(hashes []string, size int) [][]string {
	if size <= 0 {
		return nil
	}
	var batches [][]string
	for start := 0; start < len(hashes); start += size {
		end := start + size
		if end > len(hashes) {
			end = len(hashes)
		}
		batches = append(batches, hashes[start:end])
	}
	return batches
}

func parseAuthoritativeHashMembershipImportID(kind, id string) (string, error) {
	parts := strings.Split(id, ":")
	if len(parts) != 2 || parts[0] != kind || strings.TrimSpace(parts[1]) == "" {
		return "", fmt.Errorf("expected %s:target_id", kind)
	}
	return parts[1], nil
}

func legacyAuthoritativeHashMembership(kind, id string) bool {
	parts := strings.SplitN(id, ":", 3)
	return len(parts) == 3 && parts[0] == kind && strings.TrimSpace(parts[1]) != ""
}

func legacyAuthoritativeHashMigrationGuidance(kind, targetID string) string {
	return fmt.Sprintf("This v0.1 state ID uses additive hash chunks, which cannot be migrated safely during refresh. Without refreshing this resource, remove every legacy chunk for package %q from Terraform state, consolidate configuration into one %s hash resource, and import it with the canonical ID %s:%s. Do not move legacy state to the canonical resource.", targetID, kind, kind, targetID)
}

func (r *hashMembershipResource) exportedHashes(ctx context.Context, targetID string) ([]string, error) {
	var raw []byte
	var err error
	switch r.kind {
	case "application":
		raw, err = r.client.ExportApplication(ctx, targetID)
	case "baseline":
		raw, err = r.client.ExportBaseline(ctx, targetID)
	case "blocklist":
		raw, err = r.client.ExportBlocklist(ctx, targetID)
	default:
		return nil, fmt.Errorf("unsupported hash membership kind %q", r.kind)
	}
	if err != nil {
		return nil, err
	}
	return extractPackageSHA256s(raw)
}

type repositoryHashResource struct{ configuredResource }

type repositoryHashModel struct {
	ID        types.String `tfsdk:"id"`
	SHA256    types.String `tfsdk:"sha256"`
	Path      types.String `tfsdk:"path"`
	QueryJSON types.String `tfsdk:"query_json"`
}

func (r *repositoryHashResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_hash"
}
func (r *repositoryHashResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Register a SHA256 hash in the Airlock repository. Airlock does not expose a safe delete operation or return path provenance during refresh.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, Description: "SHA256 hash."},
		"sha256":     schema.StringAttribute{Required: true, Description: "SHA256 hash.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"path":       optionalComputedCreateOnlyString("Create-time associated file path. This value is preserved from configuration and is not verified during refresh."),
		"query_json": schema.StringAttribute{Computed: true, Description: "Hash query result JSON returned by Airlock."},
	}}
}
func (r *repositoryHashResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan repositoryHashModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.AddRepositoryHashes(ctx, []map[string]string{{"sha256": plan.SHA256.ValueString(), "path": plan.Path.ValueString()}}); err != nil {
		resp.Diagnostics.AddError("Unable to register Airlock hash", err.Error())
		return
	}
	plan.ID = plan.SHA256
	if !r.readHash(ctx, &plan, resp.Diagnostics.AddError) {
		if !resp.Diagnostics.HasError() {
			resp.Diagnostics.AddError("Unable to verify Airlock hash", "The hash query endpoint did not return the registered SHA256 after creation.")
		}
		return
	}
	if plan.Path.IsUnknown() {
		plan.Path = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *repositoryHashResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state repositoryHashModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !r.readHash(ctx, &state, resp.Diagnostics.AddError) {
		if !resp.Diagnostics.HasError() {
			resp.State.RemoveResource(ctx)
		}
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *repositoryHashResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var prior repositoryHashModel
	var plan repositoryHashModel
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if createOnlyMetadataAdoption(prior.Path, plan.Path) {
		plan.ID = prior.ID
		if !r.readHash(ctx, &plan, resp.Diagnostics.AddError) {
			if !resp.Diagnostics.HasError() {
				resp.State.RemoveResource(ctx)
			}
			return
		}
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		return
	}
	resp.Diagnostics.AddError("Update not supported", "Repository hashes are immutable and require replacement.")
}
func (r *repositoryHashResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}
func (r *repositoryHashResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, pathRoot("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("sha256"), req.ID)...)
}
func (r *repositoryHashResource) readHash(ctx context.Context, model *repositoryHashModel, addError func(string, string)) bool {
	results, err := r.client.QueryHashes(ctx, []string{model.SHA256.ValueString()})
	if err != nil {
		addError("Unable to query Airlock hash", err.Error())
		return false
	}
	found := false
	for _, result := range results {
		if strings.EqualFold(result.Hash, model.SHA256.ValueString()) {
			found = true
			break
		}
	}
	if !found {
		return false
	}
	b, err := json.Marshal(results)
	if err != nil {
		addError("Unable to encode Airlock hash query", err.Error())
		return false
	}
	model.QueryJSON = types.StringValue(string(b))
	return true
}

func jsonObject(raw string) (map[string]any, error) {
	var out map[string]any
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil, err
	}
	if out == nil {
		return nil, fmt.Errorf("expected JSON object")
	}
	return out, nil
}

func stringsFromSet(ctx context.Context, s types.Set) []string {
	var out []string
	_ = s.ElementsAs(ctx, &out, false)
	return out
}

func extractSHA256s(raw []byte) []string {
	hashes, _ := extractPackageSHA256s(raw)
	return hashes
}

func extractPackageSHA256s(raw []byte) ([]string, error) {
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	var hashes []string
	var shaText strings.Builder
	shaDepth := 0
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("decode Airlock package export: %w", err)
		}
		switch token := token.(type) {
		case xml.StartElement:
			if strings.EqualFold(token.Name.Local, "sha256") {
				shaDepth++
				shaText.Reset()
			}
			for _, attribute := range token.Attr {
				if strings.EqualFold(attribute.Name.Local, "sha256") {
					hashes = append(hashes, attribute.Value)
				}
			}
		case xml.CharData:
			if shaDepth > 0 {
				shaText.Write([]byte(token))
			}
		case xml.EndElement:
			if strings.EqualFold(token.Name.Local, "sha256") && shaDepth > 0 {
				hashes = append(hashes, shaText.String())
				shaDepth--
				shaText.Reset()
			}
		}
	}
	return normalizeHashes(hashes)
}
func normalizeHashes(hashes []string) ([]string, error) {
	seen := make(map[string]struct{}, len(hashes))
	for _, hash := range hashes {
		normalized := strings.ToLower(strings.TrimSpace(hash))
		if normalized == "" {
			continue
		}
		if !isSHA256(normalized) {
			return nil, fmt.Errorf("%q is not a 64-character hex SHA256", hash)
		}
		seen[normalized] = struct{}{}
	}
	out := make([]string, 0, len(seen))
	for hash := range seen {
		out = append(out, hash)
	}
	sort.Strings(out)
	return out, nil
}

func isSHA256(hash string) bool {
	if len(hash) != 64 {
		return false
	}
	for _, r := range hash {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func hashMembershipID(kind, targetID string, hashes []string) string {
	normalized, _ := normalizeHashes(hashes)
	return kind + ":" + targetID + ":" + strings.Join(normalized, ",")
}

func parseHashMembershipImportID(kind, id string) (string, []string, string, error) {
	parts := strings.SplitN(id, ":", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", nil, "", fmt.Errorf("expected kind:target_id:hash1,hash2")
	}
	if parts[0] != kind {
		return "", nil, "", fmt.Errorf("expected import ID kind %q", kind)
	}
	hashes, err := normalizeHashes(strings.Split(parts[2], ","))
	if err != nil {
		return "", nil, "", err
	}
	if len(hashes) == 0 {
		return "", nil, "", fmt.Errorf("expected at least one SHA256 hash")
	}
	return parts[1], hashes, hashMembershipID(kind, parts[1], hashes), nil
}

func hashesSubset(available, wanted []string) bool {
	normalizedAvailable, err := normalizeHashes(available)
	if err != nil {
		return false
	}
	normalizedWanted, err := normalizeHashes(wanted)
	if err != nil {
		return false
	}
	found := make(map[string]bool, len(normalizedAvailable))
	for _, hash := range normalizedAvailable {
		found[hash] = true
	}
	for _, hash := range normalizedWanted {
		if !found[hash] {
			return false
		}
	}
	return true
}

func hashesBelong(results []client.HashQueryResult, kind, targetID string, hashes []string) bool {
	found := make(map[string]bool, len(hashes))
	for _, result := range results {
		matches := false
		switch kind {
		case "application":
			for _, item := range result.Data.Applications {
				matches = matches || item.ApplicationID == targetID
			}
		case "baseline":
			for _, item := range result.Data.Baselines {
				matches = matches || item.BaselineID == targetID
			}
		case "blocklist":
			for _, item := range result.Data.Blocklists {
				matches = matches || item.BlocklistID == targetID
			}
		}
		if matches {
			found[strings.ToLower(result.Hash)] = true
		}
	}
	for _, hash := range hashes {
		if !found[strings.ToLower(hash)] {
			return false
		}
	}
	return true
}
