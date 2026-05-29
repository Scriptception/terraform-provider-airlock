package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

type simpleModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	Version          types.String `tfsdk:"version"`
	CategoryID       types.String `tfsdk:"category_id"`
	ParentCategoryID types.String `tfsdk:"parent_category_id"`
	ReferenceName    types.String `tfsdk:"reference_name"`
	Parent           types.String `tfsdk:"parent"`
	Hidden           types.Bool   `tfsdk:"hidden"`
}

type simpleSpec struct {
	TypeName    string
	Description string
	Attrs       map[string]schema.Attribute
	Create      func(context.Context, *client.Client, simpleModel) (string, error)
	Delete      func(context.Context, *client.Client, string) error
	List        func(*client.Client, context.Context) ([]client.Named, error)
}

type simpleResource struct {
	spec   simpleSpec
	client *client.Client
}

func newSimpleResource(spec simpleSpec) resource.Resource { return &simpleResource{spec: spec} }
func (r *simpleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + r.spec.TypeName
}
func (r *simpleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := map[string]schema.Attribute{"id": schema.StringAttribute{Description: "Airlock object ID.", Computed: true}}
	for k, v := range r.spec.Attrs {
		attrs[k] = v
	}
	resp.Schema = schema.Schema{Description: r.spec.Description, Attributes: attrs}
}
func (r *simpleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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
func (r *simpleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	plan := r.readSimplePlan(ctx, req.Plan)
	id, err := r.spec.Create(ctx, r.client, plan)
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Airlock "+r.spec.TypeName, err.Error())
		return
	}
	if id == "" {
		resp.Diagnostics.AddError("Unable to create Airlock "+r.spec.TypeName, "The API did not return or expose an ID for the created object.")
		return
	}
	var values map[string]attr.Value
	resp.Diagnostics.Append(req.Plan.Get(ctx, &values)...)
	if resp.Diagnostics.HasError() {
		return
	}
	values["id"] = types.StringValue(id)
	resp.Diagnostics.Append(resp.State.Set(ctx, values)...)
}
func (r *simpleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, pathRoot("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := r.spec.List(r.client, ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock "+r.spec.TypeName, err.Error())
		return
	}
	item, ok := client.FindByID(items, id.ValueString())
	if !ok {
		resp.State.RemoveResource(ctx)
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("name"), item.Name)...)
	for key, val := range item.Attrs {
		switch key {
		case "version", "parent_category_id", "parent":
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(key), val)...)
		case "hidden":
			resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot(key), val == "1")...)
		}
	}
}
func (r *simpleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "Airlock does not expose a safe update endpoint for this resource. Change requires replacement.")
}
func (r *simpleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var id types.String
	resp.Diagnostics.Append(req.State.GetAttribute(ctx, pathRoot("id"), &id)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.spec.Delete(ctx, r.client, id.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to delete Airlock "+r.spec.TypeName, err.Error())
	}
}
func (r *simpleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, pathRoot("id"), req, resp)
}

func requiredReplaceString(description string) schema.StringAttribute {
	return schema.StringAttribute{Required: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func optionalReplaceString(description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}}
}

func optionalComputedReplaceString(description string) schema.StringAttribute {
	return schema.StringAttribute{Optional: true, Computed: true, Description: description, PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace(), stringplanmodifier.UseStateForUnknown()}}
}

func optionalComputedReplaceBool(description string) schema.BoolAttribute {
	return schema.BoolAttribute{Optional: true, Computed: true, Description: description, PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace(), boolplanmodifier.UseStateForUnknown()}}
}

type simplePlanGetter interface {
	GetAttribute(context.Context, path.Path, interface{}) diag.Diagnostics
}

func (r *simpleResource) readSimplePlan(ctx context.Context, plan simplePlanGetter) simpleModel {
	var model simpleModel
	_ = plan.GetAttribute(ctx, pathRoot("id"), &model.ID)
	_ = plan.GetAttribute(ctx, pathRoot("name"), &model.Name)
	_ = plan.GetAttribute(ctx, pathRoot("version"), &model.Version)
	_ = plan.GetAttribute(ctx, pathRoot("category_id"), &model.CategoryID)
	_ = plan.GetAttribute(ctx, pathRoot("parent_category_id"), &model.ParentCategoryID)
	_ = plan.GetAttribute(ctx, pathRoot("reference_name"), &model.ReferenceName)
	_ = plan.GetAttribute(ctx, pathRoot("parent"), &model.Parent)
	_ = plan.GetAttribute(ctx, pathRoot("hidden"), &model.Hidden)
	return model
}

func NewApplicationResource() resource.Resource {
	return newSimpleResource(simpleSpec{TypeName: "application", Description: "Manage an Airlock allowlist application package.", Attrs: map[string]schema.Attribute{
		"name":        requiredReplaceString("Application package name."),
		"version":     optionalComputedReplaceString("Application package version."),
		"category_id": optionalReplaceString("Application category ID."),
	}, Create: func(ctx context.Context, c *client.Client, m simpleModel) (string, error) {
		return c.CreateApplication(ctx, m.Name.ValueString(), m.Version.ValueString(), m.CategoryID.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, id string) error { return c.DeleteApplication(ctx, id) }, List: (*client.Client).ListApplications})
}
func NewApplicationCategoryResource() resource.Resource {
	return newSimpleResource(simpleSpec{TypeName: "application_category", Description: "Manage an Airlock application category or subcategory.", Attrs: map[string]schema.Attribute{
		"name":               requiredReplaceString("Category name."),
		"parent_category_id": requiredReplaceString("Parent category ID. Airlock creates categories beneath an existing parent category."),
	}, Create: func(ctx context.Context, c *client.Client, m simpleModel) (string, error) {
		return c.CreateApplicationCategory(ctx, m.Name.ValueString(), m.ParentCategoryID.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, id string) error {
		return c.DeleteApplicationCategory(ctx, id)
	}, List: (*client.Client).ListApplicationCategories})
}
func NewBaselineResource() resource.Resource {
	return newSimpleResource(simpleSpec{TypeName: "baseline", Description: "Manage an Airlock baseline package or import an Airlock reference baseline.", Attrs: map[string]schema.Attribute{
		"name":           requiredReplaceString("Baseline name."),
		"reference_name": optionalReplaceString("Reference baseline name to import instead of creating an empty baseline."),
	}, Create: func(ctx context.Context, c *client.Client, m simpleModel) (string, error) {
		if !m.ReferenceName.IsNull() && !m.ReferenceName.IsUnknown() && m.ReferenceName.ValueString() != "" {
			if err := c.ImportReferenceBaseline(ctx, m.ReferenceName.ValueString()); err != nil {
				return "", err
			}
			items, err := c.ListBaselines(ctx)
			if err != nil {
				return "", err
			}
			if item, ok := client.FindByName(items, m.ReferenceName.ValueString()); ok {
				return item.ID, nil
			}
			if item, ok := client.FindByName(items, m.Name.ValueString()); ok {
				return item.ID, nil
			}
			return "", nil
		}
		return c.CreateBaseline(ctx, m.Name.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, id string) error { return c.DeleteBaseline(ctx, id) }, List: (*client.Client).ListBaselines})
}
func NewBlocklistResource() resource.Resource {
	return newSimpleResource(simpleSpec{TypeName: "blocklist", Description: "Manage an Airlock blocklist package.", Attrs: map[string]schema.Attribute{"name": requiredReplaceString("Blocklist name.")}, Create: func(ctx context.Context, c *client.Client, m simpleModel) (string, error) {
		return c.CreateBlocklist(ctx, m.Name.ValueString())
	}, Delete: func(ctx context.Context, c *client.Client, id string) error { return c.DeleteBlocklist(ctx, id) }, List: (*client.Client).ListBlocklists})
}
func NewGroupResource() resource.Resource {
	return newSimpleResource(simpleSpec{TypeName: "group", Description: "Manage an Airlock policy group.", Attrs: map[string]schema.Attribute{
		"name":   requiredReplaceString("Group name."),
		"parent": optionalComputedReplaceString("Parent group name or ID, if Airlock requires one."),
		"hidden": optionalComputedReplaceBool("Whether the group is hidden."),
	}, Create: func(ctx context.Context, c *client.Client, m simpleModel) (string, error) {
		return c.CreateGroup(ctx, m.Name.ValueString(), m.Parent.ValueString(), m.Hidden.ValueBool())
	}, Delete: func(ctx context.Context, c *client.Client, id string) error { return c.DeleteGroup(ctx, id) }, List: (*client.Client).ListGroups})
}
