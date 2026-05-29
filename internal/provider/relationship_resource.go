package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

type relModel struct {
	ID       types.String `tfsdk:"id"`
	GroupID  types.String `tfsdk:"group_id"`
	TargetID types.String `tfsdk:"target_id"`
	Value    types.String `tfsdk:"value"`
	Type     types.String `tfsdk:"type"`
	Comment  types.String `tfsdk:"comment"`
	Audit    types.Bool   `tfsdk:"audit"`
}

type relSpec struct {
	TypeName    string
	Description string
	Attrs       map[string]schema.Attribute
	Create      func(context.Context, *client.Client, relModel) error
	Delete      func(context.Context, *client.Client, relModel) error
	Read        func(context.Context, *client.Client, relModel) (relModel, bool, error)
	ID          func(relModel) string
	Import      func(context.Context, resource.ImportStateRequest, *resource.ImportStateResponse)
}

type relResource struct {
	spec   relSpec
	client *client.Client
}

func newRelResource(spec relSpec) resource.Resource { return &relResource{spec: spec} }
func (r *relResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.spec.TypeName
}
func (r *relResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{"id": schema.StringAttribute{Computed: true, Description: "Stable Terraform import ID for this Airlock relationship."}}
	for k, v := range r.spec.Attrs {
		attrs[k] = v
	}
	resp.Schema = schema.Schema{Description: r.spec.Description, Attributes: attrs}
}
func (r *relResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *relResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan relModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.spec.Create(ctx, r.client, plan); err != nil {
		resp.Diagnostics.AddError("Unable to create Airlock "+r.spec.TypeName, err.Error())
		return
	}
	plan.ID = types.StringValue(r.spec.ID(plan))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *relResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state relModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if r.spec.Read != nil {
		next, ok, err := r.spec.Read(ctx, r.client, state)
		if err != nil {
			resp.Diagnostics.AddError("Unable to read Airlock "+r.spec.TypeName, err.Error())
			return
		}
		if !ok {
			resp.State.RemoveResource(ctx)
			return
		}
		next.ID = types.StringValue(r.spec.ID(next))
		resp.Diagnostics.Append(resp.State.Set(ctx, &next)...)
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
func (r *relResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan relModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.spec.Create(ctx, r.client, plan); err != nil {
		resp.Diagnostics.AddError("Unable to update Airlock "+r.spec.TypeName, err.Error())
		return
	}
	plan.ID = types.StringValue(r.spec.ID(plan))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}
func (r *relResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state relModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.spec.Delete(ctx, r.client, state); err != nil {
		resp.Diagnostics.AddError("Unable to delete Airlock "+r.spec.TypeName, err.Error())
	}
}
func (r *relResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	if r.spec.Import != nil {
		r.spec.Import(ctx, req, resp)
		return
	}
	resource.ImportStatePassthroughID(ctx, pathRoot("id"), req, resp)
}

func importTwoPart(firstAttr, secondAttr string) func(context.Context, resource.ImportStateRequest, *resource.ImportStateResponse) {
	return func(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
		parts := strings.SplitN(req.ID, ":", 2)
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
			resp.Diagnostics.AddError("Invalid import ID", "Expected import ID in the form first:second.")
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(firstAttr), parts[0])...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(secondAttr), parts[1])...)
	}
}
func importThreePart(firstAttr, secondAttr, thirdAttr string) func(context.Context, resource.ImportStateRequest, *resource.ImportStateResponse) {
	return func(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
		parts := strings.SplitN(req.ID, ":", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			resp.Diagnostics.AddError("Invalid import ID", "Expected import ID in the form first:second:third.")
			return
		}
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(firstAttr), parts[0])...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(secondAttr), parts[1])...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(thirdAttr), parts[2])...)
	}
}
func requiredRelString(description string) schema.StringAttribute {
	return schema.StringAttribute{Required: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func optionalRelString(description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Computed: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}}
}

func optionalRelBool(description string) schema.BoolAttribute {
	return schema.BoolAttribute{Optional: true, Description: description, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()}}
}

var groupIDAttr = requiredRelString("Airlock policy group ID.")

func readGroupApplication(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Applications {
		if item.ID == m.TargetID.ValueString() {
			return m, true, nil
		}
	}
	return m, false, nil
}

func readGroupBaseline(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Baselines {
		if item.ID == m.TargetID.ValueString() {
			return m, true, nil
		}
	}
	return m, false, nil
}

func readGroupBlocklist(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Blocklists {
		if item.ID == m.TargetID.ValueString() {
			return m, true, nil
		}
	}
	return m, false, nil
}

func readGroupPath(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Paths {
		if item.Name == m.Value.ValueString() {
			m.Comment = types.StringValue(item.Attrs["comment"])
			return m, true, nil
		}
	}
	return m, false, nil
}

func readGroupProcess(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Processes {
		if item.Name == m.Value.ValueString() && item.Attrs["type"] == m.Type.ValueString() {
			m.Comment = types.StringValue(item.Attrs["comment"])
			return m, true, nil
		}
	}
	return m, false, nil
}

func readGroupPublisher(ctx context.Context, c *client.Client, m relModel) (relModel, bool, error) {
	p, err := c.GetGroupPolicy(ctx, m.GroupID.ValueString())
	if err != nil {
		return m, false, err
	}
	for _, item := range p.Publishers {
		if item.Name == m.Value.ValueString() {
			m.Comment = types.StringValue(item.Attrs["comment"])
			return m, true, nil
		}
	}
	return m, false, nil
}

func NewGroupApplicationPolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_application_policy", Description: "Approve an Airlock allowlist application package for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": requiredRelString("Application ID.")}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Read: readGroupApplication, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupApplication(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true)
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupApplication(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false)
	}})
}
func NewGroupBaselinePolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_baseline_policy", Description: "Approve an Airlock baseline for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": requiredRelString("Baseline ID.")}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Read: readGroupBaseline, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBaseline(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true)
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBaseline(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false)
	}})
}
func NewGroupBlocklistPolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_blocklist_policy", Description: "Approve an Airlock blocklist for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": requiredRelString("Blocklist ID."), "audit": optionalRelBool("Enable audit mode for the blocklist approval.")}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Read: readGroupBlocklist, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBlocklist(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true, m.Audit.ValueBool())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBlocklist(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false, false)
	}})
}
func NewGroupPathResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_path", Description: "Manage a trusted path entry on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": requiredRelString("Path pattern."), "comment": optionalRelString("Comment.")}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.Value.ValueString() }, Import: importTwoPart("group_id", "value"), Read: readGroupPath, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupPath(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupPath(ctx, m.GroupID.ValueString(), m.Value.ValueString())
	}})
}
func NewGroupProcessResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_process", Description: "Manage a parent or grandparent process rule on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": requiredRelString("Process name."), "type": schema.StringAttribute{Required: true, Description: "Process type: pprocess or gprocess.", Validators: []validator.String{stringOneOfValidator{allowed: []string{"pprocess", "gprocess"}}}, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}, "comment": optionalRelString("Comment.")}, ID: func(m relModel) string {
		return m.GroupID.ValueString() + ":" + m.Type.ValueString() + ":" + m.Value.ValueString()
	}, Import: importThreePart("group_id", "type", "value"), Read: readGroupProcess, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupProcess(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Type.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupProcess(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Type.ValueString())
	}})
}
func NewGroupPublisherResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_publisher", Description: "Manage a trusted publisher entry on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": requiredRelString("Publisher name."), "comment": optionalRelString("Comment.")}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.Value.ValueString() }, Import: importTwoPart("group_id", "value"), Read: readGroupPublisher, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupPublisher(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupPublisher(ctx, m.GroupID.ValueString(), m.Value.ValueString())
	}})
}
