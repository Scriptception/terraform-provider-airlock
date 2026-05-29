package provider

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

type listDataSource struct {
	typeName, description string
	list                  func(*client.Client, context.Context) ([]client.Named, error)
	client                *client.Client
}
type listDataSourceModel struct {
	ID        types.String `tfsdk:"id"`
	Name      types.String `tfsdk:"name"`
	ItemsJSON types.String `tfsdk:"items_json"`
	FirstID   types.String `tfsdk:"first_id"`
}

func newListDataSource(t, d string, l func(*client.Client, context.Context) ([]client.Named, error)) datasource.DataSource {
	return &listDataSource{typeName: t, description: d, list: l}
}
func (d *listDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.typeName
}
func (d *listDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: d.description, Attributes: map[string]schema.Attribute{
		"id":         schema.StringAttribute{Optional: true, Description: "Filter by exact Airlock ID."},
		"name":       schema.StringAttribute{Optional: true, Description: "Filter by exact Airlock name."},
		"first_id":   schema.StringAttribute{Computed: true, Description: "The first matching Airlock ID, useful when filtering by name."},
		"items_json": schema.StringAttribute{Computed: true, Description: "JSON array of matching objects returned by Airlock, with IDs, names, and non-sensitive attributes."},
	}}
}
func (d *listDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("Unexpected provider data", fmt.Sprintf("Expected *client.Client, got %T", req.ProviderData))
		return
	}
	d.client = c
}
func (d *listDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg listDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}
	items, err := d.list(d.client, ctx)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock "+d.typeName, err.Error())
		return
	}
	filtered := make([]client.Named, 0, len(items))
	for _, item := range items {
		if !cfg.ID.IsNull() && cfg.ID.ValueString() != "" && item.ID != cfg.ID.ValueString() {
			continue
		}
		if !cfg.Name.IsNull() && cfg.Name.ValueString() != "" && item.Name != cfg.Name.ValueString() {
			continue
		}
		filtered = append(filtered, item)
	}
	b, err := json.Marshal(filtered)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode Airlock "+d.typeName, err.Error())
		return
	}
	cfg.ItemsJSON = types.StringValue(string(b))
	if len(filtered) > 0 {
		cfg.FirstID = types.StringValue(filtered[0].ID)
	} else {
		cfg.FirstID = types.StringNull()
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &cfg)...)
}
func NewApplicationsDataSource() datasource.DataSource {
	return newListDataSource("applications", "List or lookup Airlock allowlist application packages.", (*client.Client).ListApplications)
}
func NewApplicationCategoriesDataSource() datasource.DataSource {
	return newListDataSource("application_categories", "List or lookup Airlock application categories.", (*client.Client).ListApplicationCategories)
}
func NewBaselinesDataSource() datasource.DataSource {
	return newListDataSource("baselines", "List or lookup Airlock baselines.", (*client.Client).ListBaselines)
}
func NewBlocklistsDataSource() datasource.DataSource {
	return newListDataSource("blocklists", "List or lookup Airlock blocklists.", (*client.Client).ListBlocklists)
}
func NewGroupsDataSource() datasource.DataSource {
	return newListDataSource("groups", "List or lookup Airlock policy groups.", (*client.Client).ListGroups)
}
func NewAgentsDataSource() datasource.DataSource {
	return newListDataSource("agents", "List or lookup Airlock agents. This data source is read-only and should not be used to commit host details into public configuration.", (*client.Client).ListAgents)
}
