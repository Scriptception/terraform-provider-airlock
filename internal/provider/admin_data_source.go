package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

type configuredDataSource struct{ client *client.Client }

func (d *configuredDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

type jsonDataSource struct {
	configuredDataSource
	typeName    string
	description string
	read        func(context.Context, *client.Client, map[string]string) (any, error)
}

func newJSONDataSource(typeName, description string, read func(context.Context, *client.Client, map[string]string) (any, error)) datasource.DataSource {
	return &jsonDataSource{typeName: typeName, description: description, read: read}
}
func (d *jsonDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_" + d.typeName
}
func (d *jsonDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	attrs := map[string]schema.Attribute{
		"items_json": schema.StringAttribute{Computed: true, Sensitive: true, Description: "JSON response returned by Airlock. Marked sensitive because administrative data may include environment details."},
	}
	switch d.typeName {
	case "group_policy", "group_agents":
		attrs["group_id"] = schema.StringAttribute{Required: true, Description: "Airlock policy group ID."}
	case "hash_query":
		attrs["hashes"] = schema.SetAttribute{Required: true, ElementType: types.StringType, Description: "SHA256 hashes to query."}
	}
	resp.Schema = schema.Schema{Description: d.description, Attributes: attrs}
}
func (d *jsonDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	args := map[string]string{}
	var groupID types.String
	var hashes types.Set
	if d.typeName == "group_policy" || d.typeName == "group_agents" {
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("group_id"), &groupID)...)
		if resp.Diagnostics.HasError() {
			return
		}
		args["group_id"] = groupID.ValueString()
	}
	if d.typeName == "hash_query" {
		resp.Diagnostics.Append(req.Config.GetAttribute(ctx, pathRoot("hashes"), &hashes)...)
		if resp.Diagnostics.HasError() {
			return
		}
		args["hashes"] = strings.Join(stringsFromSet(ctx, hashes), ",")
	}
	out, err := d.read(ctx, d.client, args)
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock "+d.typeName, err.Error())
		return
	}
	b, err := json.Marshal(out)
	if err != nil {
		resp.Diagnostics.AddError("Unable to encode Airlock "+d.typeName, err.Error())
		return
	}
	if !groupID.IsNull() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), groupID)...)
	}
	if !hashes.IsNull() {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("hashes"), hashes)...)
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("items_json"), string(b))...)
}

func NewGroupPolicyDataSource() datasource.DataSource {
	return newJSONDataSource("group_policy", "Read the complete effective policy for an Airlock policy group.", func(ctx context.Context, c *client.Client, args map[string]string) (any, error) {
		return c.GetGroupPolicyRaw(ctx, args["group_id"])
	})
}

func NewGroupAgentsDataSource() datasource.DataSource {
	return newJSONDataSource("group_agents", "Read agents assigned to an Airlock policy group.", func(ctx context.Context, c *client.Client, args map[string]string) (any, error) {
		return c.ListGroupAgentsRaw(ctx, args["group_id"])
	})
}

func NewCommunicationListsDataSource() datasource.DataSource {
	return newJSONDataSource("communication_lists", "Read Airlock communication lists.", func(ctx context.Context, c *client.Client, _ map[string]string) (any, error) {
		return c.ListCommunicationLists(ctx)
	})
}

func NewDomainGroupsDataSource() datasource.DataSource {
	return newJSONDataSource("domain_groups", "Read domain security groups known to Airlock.", func(ctx context.Context, c *client.Client, _ map[string]string) (any, error) {
		return c.ListDomainGroups(ctx)
	})
}

func NewCloudGroupsDataSource() datasource.DataSource {
	return newJSONDataSource("cloud_groups", "Read cloud security groups known to Airlock.", func(ctx context.Context, c *client.Client, _ map[string]string) (any, error) {
		return c.ListCloudGroups(ctx)
	})
}

func NewReferenceBaselinesDataSource() datasource.DataSource {
	return newListDataSource("reference_baselines", "List Airlock reference baselines available to import.", (*client.Client).ListReferenceBaselines)
}

func NewHashQueryDataSource() datasource.DataSource {
	return newJSONDataSource("hash_query", "Query Airlock's hash repository for package membership.", func(ctx context.Context, c *client.Client, args map[string]string) (any, error) {
		return c.QueryHashes(ctx, strings.Split(args["hashes"], ","))
	})
}
