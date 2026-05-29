package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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

type groupSettingsResource struct{ configuredResource }

type groupSettingsModel struct {
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
	resp.Schema = schema.Schema{Description: "Manage durable settings for an Airlock policy group using the update-all settings API. The settings JSON must contain the full desired settings payload for the group.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true, Description: "Airlock policy group ID."},
		"group_id":      schema.StringAttribute{Required: true, Description: "Airlock policy group ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"settings_json": schema.StringAttribute{Required: true, Sensitive: true, Description: "JSON object sent to Airlock's group settings update-all endpoint. The provider injects groupid from group_id."},
		"policy_json":   schema.StringAttribute{Computed: true, Sensitive: true, Description: "Current group policy JSON returned by Airlock after refresh. Marked sensitive because policy data may include proxy or environment details."},
	}}
}
func (r *groupSettingsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	settings, err := jsonObject(plan.SettingsJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(pathRoot("settings_json"), "Invalid settings JSON", err.Error())
		return
	}
	settings["groupid"] = plan.GroupID.ValueString()
	if err := r.client.UpdateGroupSettings(ctx, settings); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock group settings", err.Error())
		return
	}
	plan.ID = plan.GroupID
	r.readPolicy(ctx, &plan, resp.Diagnostics.AddError)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *groupSettingsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupSettingsModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readPolicy(ctx, &state, resp.Diagnostics.AddError)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *groupSettingsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan groupSettingsModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	settings, err := jsonObject(plan.SettingsJSON.ValueString())
	if err != nil {
		resp.Diagnostics.AddAttributeError(pathRoot("settings_json"), "Invalid settings JSON", err.Error())
		return
	}
	settings["groupid"] = plan.GroupID.ValueString()
	if err := r.client.UpdateGroupSettings(ctx, settings); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock group settings", err.Error())
		return
	}
	plan.ID = plan.GroupID
	r.readPolicy(ctx, &plan, resp.Diagnostics.AddError)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *groupSettingsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
}
func (r *groupSettingsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), req.ID)...)
}
func (r *groupSettingsResource) readPolicy(ctx context.Context, model *groupSettingsModel, addError func(string, string)) {
	policy, err := r.client.GetGroupPolicyRaw(ctx, model.GroupID.ValueString())
	if err != nil {
		addError("Unable to read Airlock group policy", err.Error())
		return
	}
	b, err := json.Marshal(policy)
	if err != nil {
		addError("Unable to encode Airlock group policy", err.Error())
		return
	}
	model.PolicyJSON = types.StringValue(string(b))
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
	CriteriaJSON types.String `tfsdk:"criteria_json"`
	SettingsJSON types.String `tfsdk:"settings_json"`
}

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
	resp.Schema = schema.Schema{Description: "Manage an Airlock " + string(r.kind) + " metarule.", Attributes: map[string]schema.Attribute{
		"id":            schema.StringAttribute{Computed: true, Description: "Airlock metarule UUID."},
		"package_id":    schema.StringAttribute{Required: true, Description: "Target Airlock package ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"name":          schema.StringAttribute{Required: true, Description: "Metarule name."},
		"os":            schema.StringAttribute{Required: true, Description: "Operating system: windows, linux, or mac.", Validators: []validator.String{stringOneOfValidator{allowed: []string{"windows", "linux", "mac"}}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"criteria_json": schema.StringAttribute{Required: true, Description: "JSON array of 1-5 Airlock metarule criteria objects.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"settings_json": schema.StringAttribute{Optional: true, Computed: true, Description: "Optional JSON object of Airlock metarule settings.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}},
	}}
}
func (r *metaruleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan metaruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	body, err := r.metaruleBody(plan)
	if err != nil {
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
				state.CriteriaJSON = types.StringValue(string(rule.Criteria))
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
			return
		}
	}
	resp.State.RemoveResource(ctx)
}
func (r *metaruleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan metaruleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	var err error
	if r.kind == applicationMetarule {
		err = r.client.UpdateApplicationMetaruleName(ctx, plan.ID.ValueString(), plan.Name.ValueString())
	} else {
		err = r.client.UpdateBlocklistMetaruleName(ctx, plan.ID.ValueString(), plan.Name.ValueString())
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
func (r *metaruleResource) metaruleBody(m metaruleModel) (map[string]any, error) {
	var criteria any
	if err := json.Unmarshal([]byte(m.CriteriaJSON.ValueString()), &criteria); err != nil {
		return nil, fmt.Errorf("criteria_json must be valid JSON: %w", err)
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
	resp.Schema = schema.Schema{Description: "Manage SHA256 hash membership for an Airlock " + r.kind + " package.", Attributes: map[string]schema.Attribute{
		"id":        schema.StringAttribute{Computed: true, Description: "Stable Terraform ID."},
		"target_id": schema.StringAttribute{Required: true, Description: "Target Airlock package ID.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"hashes":    schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "SHA256 hashes.", PlanModifiers: []planmodifier.Set{setplanmodifier.RequiresReplace()}},
	}}
}
func (r *hashMembershipResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan hashMembershipModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hashes := stringsFromSet(ctx, plan.Hashes)
	var err error
	switch r.kind {
	case "application":
		err = r.client.AddApplicationHash(ctx, plan.TargetID.ValueString(), hashes)
	case "baseline":
		err = r.client.AddBaselineHash(ctx, plan.TargetID.ValueString(), hashes)
	case "blocklist":
		err = r.client.AddBlocklistHash(ctx, plan.TargetID.ValueString(), hashes)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to add Airlock hashes", err.Error())
		return
	}
	plan.ID = types.StringValue(r.kind + ":" + plan.TargetID.ValueString() + ":" + strings.Join(hashes, ","))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *hashMembershipResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state hashMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hashes := stringsFromSet(ctx, state.Hashes)
	results, err := r.client.QueryHashes(ctx, hashes)
	if err != nil {
		resp.Diagnostics.AddError("Unable to query Airlock hashes", err.Error())
		return
	}
	if !hashesBelong(results, r.kind, state.TargetID.ValueString(), hashes) {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *hashMembershipResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Hash membership changes require replacement.")
}
func (r *hashMembershipResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state hashMembershipModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	hashes := stringsFromSet(ctx, state.Hashes)
	var err error
	switch r.kind {
	case "application":
		err = r.client.RemoveApplicationHash(ctx, state.TargetID.ValueString(), hashes)
	case "baseline":
		err = r.client.RemoveBaselineHash(ctx, state.TargetID.ValueString(), hashes)
	case "blocklist":
		err = r.client.RemoveBlocklistHash(ctx, state.TargetID.ValueString(), hashes)
	}
	if err != nil {
		resp.Diagnostics.AddError("Unable to remove Airlock hashes", err.Error())
	}
}
func (r *hashMembershipResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 3)
	if len(parts) != 3 {
		resp.Diagnostics.AddError("Invalid import ID", "Expected kind:target_id:hash1,hash2.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("target_id"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("hashes"), strings.Split(parts[2], ","))...)
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
	resp.Schema = schema.Schema{Description: "Register a SHA256 hash in the Airlock repository.", Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Computed: true, Description: "SHA256 hash."},
		"sha256":     schema.StringAttribute{Required: true, Description: "SHA256 hash.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"path":       schema.StringAttribute{Required: true, Description: "Associated file path.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
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
	r.readHash(ctx, &plan, resp.Diagnostics.AddError)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *repositoryHashResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state repositoryHashModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	r.readHash(ctx, &state, resp.Diagnostics.AddError)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *repositoryHashResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Repository hashes are immutable and require replacement.")
}
func (r *repositoryHashResource) Delete(context.Context, resource.DeleteRequest, *resource.DeleteResponse) {
}
func (r *repositoryHashResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, pathRoot("id"), req, resp)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("sha256"), req.ID)...)
}
func (r *repositoryHashResource) readHash(ctx context.Context, model *repositoryHashModel, addError func(string, string)) {
	results, err := r.client.QueryHashes(ctx, []string{model.SHA256.ValueString()})
	if err != nil {
		addError("Unable to query Airlock hash", err.Error())
		return
	}
	b, err := json.Marshal(results)
	if err != nil {
		addError("Unable to encode Airlock hash query", err.Error())
		return
	}
	model.QueryJSON = types.StringValue(string(b))
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
