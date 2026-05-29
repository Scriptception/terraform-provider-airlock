package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
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
	Hashes   types.List   `tfsdk:"hashes"`
	Path     types.String `tfsdk:"path"`
	SHA256   types.String `tfsdk:"sha256"`
}

type relSpec struct {
	TypeName    string
	Description string
	Attrs       map[string]schema.Attribute
	Create      func(context.Context, *client.Client, relModel) error
	Delete      func(context.Context, *client.Client, relModel) error
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
	for k, v := range map[string]schema.Attribute{
		"group_id":  schema.StringAttribute{Computed: true, Description: "Airlock policy group ID."},
		"target_id": schema.StringAttribute{Computed: true, Description: "Target Airlock object ID."},
		"value":     schema.StringAttribute{Computed: true, Description: "Relationship value."},
		"type":      schema.StringAttribute{Computed: true, Description: "Relationship type."},
		"comment":   schema.StringAttribute{Computed: true, Description: "Comment."},
		"audit":     schema.BoolAttribute{Computed: true, Description: "Audit mode."},
		"hashes":    schema.ListAttribute{Computed: true, ElementType: types.StringType, Description: "SHA256 hashes."},
		"path":      schema.StringAttribute{Computed: true, Description: "Associated path."},
		"sha256":    schema.StringAttribute{Computed: true, Description: "SHA256 hash."},
	} {
		if _, ok := attrs[k]; !ok {
			attrs[k] = v
		}
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

func stringsFromList(ctx context.Context, l types.List) []string {
	var out []string
	_ = l.ElementsAs(ctx, &out, false)
	return out
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
func importHash(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("sha256"), req.ID)...)
}

var groupIDAttr = schema.StringAttribute{Required: true, Description: "Airlock policy group ID."}
var hashesAttr = schema.ListAttribute{Required: true, ElementType: types.StringType, Description: "SHA256 hashes managed by this relationship."}

func NewGroupApplicationPolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_application_policy", Description: "Approve an Airlock allowlist application package for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": schema.StringAttribute{Required: true, Description: "Application ID."}}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupApplication(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true)
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupApplication(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false)
	}})
}
func NewGroupBaselinePolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_baseline_policy", Description: "Approve an Airlock baseline for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": schema.StringAttribute{Required: true, Description: "Baseline ID."}}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBaseline(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true)
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBaseline(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false)
	}})
}
func NewGroupBlocklistPolicyResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_blocklist_policy", Description: "Approve an Airlock blocklist for a policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "target_id": schema.StringAttribute{Required: true, Description: "Blocklist ID."}, "audit": schema.BoolAttribute{Optional: true, Description: "Enable audit mode for the blocklist approval."}}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.TargetID.ValueString() }, Import: importTwoPart("group_id", "target_id"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBlocklist(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), true, m.Audit.ValueBool())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.SetGroupBlocklist(ctx, m.GroupID.ValueString(), m.TargetID.ValueString(), false, false)
	}})
}
func NewGroupPathResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_path", Description: "Manage a trusted path entry on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": schema.StringAttribute{Required: true, Description: "Path pattern."}, "comment": schema.StringAttribute{Optional: true, Description: "Comment."}}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.Value.ValueString() }, Import: importTwoPart("group_id", "value"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupPath(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupPath(ctx, m.GroupID.ValueString(), m.Value.ValueString())
	}})
}
func NewGroupProcessResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_process", Description: "Manage a parent or grandparent process rule on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": schema.StringAttribute{Required: true, Description: "Process name."}, "type": schema.StringAttribute{Required: true, Description: "Process type: pprocess or gprocess."}, "comment": schema.StringAttribute{Optional: true, Description: "Comment."}}, ID: func(m relModel) string {
		return m.GroupID.ValueString() + ":" + m.Type.ValueString() + ":" + m.Value.ValueString()
	}, Import: importThreePart("group_id", "type", "value"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupProcess(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Type.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupProcess(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Type.ValueString())
	}})
}
func NewGroupPublisherResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "group_publisher", Description: "Manage a trusted publisher entry on an Airlock policy group.", Attrs: map[string]schema.Attribute{"group_id": groupIDAttr, "value": schema.StringAttribute{Required: true, Description: "Publisher name."}, "comment": schema.StringAttribute{Optional: true, Description: "Comment."}}, ID: func(m relModel) string { return m.GroupID.ValueString() + ":" + m.Value.ValueString() }, Import: importTwoPart("group_id", "value"), Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddGroupPublisher(ctx, m.GroupID.ValueString(), m.Value.ValueString(), m.Comment.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveGroupPublisher(ctx, m.GroupID.ValueString(), m.Value.ValueString())
	}})
}
func NewHashResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "hash", Description: "Register a SHA256 hash in Airlock's hash inventory.", Attrs: map[string]schema.Attribute{"sha256": schema.StringAttribute{Required: true, Description: "SHA256 hash."}, "path": schema.StringAttribute{Optional: true, Description: "Associated path."}}, ID: func(m relModel) string { return m.SHA256.ValueString() }, Import: importHash, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddHash(ctx, m.SHA256.ValueString(), m.Path.ValueString())
	}, Delete: func(context.Context, *client.Client, relModel) error { return nil }})
}
func NewApplicationHashResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "application_hash", Description: "Attach hashes to an Airlock allowlist application package.", Attrs: map[string]schema.Attribute{"target_id": schema.StringAttribute{Required: true, Description: "Application ID."}, "hashes": hashesAttr}, ID: func(m relModel) string {
		return "application:" + m.TargetID.ValueString() + ":" + strings.Join(stringsFromList(context.Background(), m.Hashes), ",")
	}, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddApplicationHash(ctx, m.TargetID.ValueString(), stringsFromList(ctx, m.Hashes))
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveApplicationHash(ctx, m.TargetID.ValueString(), stringsFromList(ctx, m.Hashes))
	}})
}
func NewBaselineHashResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "baseline_hash", Description: "Attach hashes to an Airlock baseline.", Attrs: map[string]schema.Attribute{"target_id": schema.StringAttribute{Required: true, Description: "Baseline ID."}, "hashes": hashesAttr}, ID: func(m relModel) string {
		return "baseline:" + m.TargetID.ValueString() + ":" + strings.Join(stringsFromList(context.Background(), m.Hashes), ",")
	}, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddBaselineHash(ctx, m.TargetID.ValueString(), stringsFromList(ctx, m.Hashes))
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveBaselineHash(ctx, m.TargetID.ValueString(), stringsFromList(ctx, m.Hashes))
	}})
}
func NewBlocklistHashResource() resource.Resource {
	return newRelResource(relSpec{TypeName: "blocklist_hash", Description: "Attach hashes to the Airlock blocklist hash set.", Attrs: map[string]schema.Attribute{"hashes": hashesAttr}, ID: func(m relModel) string {
		return "blocklist:" + strings.Join(stringsFromList(context.Background(), m.Hashes), ",")
	}, Create: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.AddBlocklistHash(ctx, stringsFromList(ctx, m.Hashes))
	}, Delete: func(ctx context.Context, c *client.Client, m relModel) error {
		return c.RemoveBlocklistHash(ctx, stringsFromList(ctx, m.Hashes))
	}})
}
