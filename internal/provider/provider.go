package provider

import (
	"context"
	"os"
	"strconv"
	"time"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/function"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

var _ provider.Provider = (*AirlockProvider)(nil)

type AirlockProvider struct{ version string }

type providerModel struct {
	URL            types.String `tfsdk:"url"`
	APIKey         types.String `tfsdk:"api_key"`
	Insecure       types.Bool   `tfsdk:"insecure"`
	TimeoutSeconds types.Int64  `tfsdk:"timeout_seconds"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider { return &AirlockProvider{version: version} }
}
func (p *AirlockProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "airlock"
	resp.Version = p.version
}
func (p *AirlockProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Manage Airlock Digital application control configuration as code.", Attributes: map[string]schema.Attribute{
		"url":             schema.StringAttribute{Description: "Base URL of the Airlock REST API, for example `https://airlock.example.com:3129`. May also be set via AIRLOCK_URL.", Optional: true, Validators: []validator.String{urlValidator{}}},
		"api_key":         schema.StringAttribute{Description: "Airlock API key. May also be set via AIRLOCK_API_KEY.", Optional: true, Sensitive: true},
		"insecure":        schema.BoolAttribute{Description: "Skip TLS certificate verification. May also be set via AIRLOCK_INSECURE. Disabled by default.", Optional: true},
		"timeout_seconds": schema.Int64Attribute{Description: "HTTP request timeout in seconds. May also be set via AIRLOCK_TIMEOUT_SECONDS. Defaults to 30.", Optional: true, Validators: []validator.Int64{positiveInt64Validator{}}},
	}}
}
func (p *AirlockProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var data providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}
	url := firstNonEmpty(data.URL.ValueString(), os.Getenv("AIRLOCK_URL"))
	apiKey := firstNonEmpty(data.APIKey.ValueString(), os.Getenv("AIRLOCK_API_KEY"))
	insecure := false
	if !data.Insecure.IsNull() && !data.Insecure.IsUnknown() {
		insecure = data.Insecure.ValueBool()
	} else if v, err := strconv.ParseBool(os.Getenv("AIRLOCK_INSECURE")); err == nil {
		insecure = v
	}
	timeout := int64(30)
	if !data.TimeoutSeconds.IsNull() && !data.TimeoutSeconds.IsUnknown() {
		timeout = data.TimeoutSeconds.ValueInt64()
	} else if v, err := strconv.ParseInt(os.Getenv("AIRLOCK_TIMEOUT_SECONDS"), 10, 64); err == nil && v > 0 {
		timeout = v
	}
	if url == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("url"), "Missing Airlock URL", "Set the url attribute or AIRLOCK_URL environment variable.")
	}
	if apiKey == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("api_key"), "Missing Airlock API key", "Set the api_key attribute or AIRLOCK_API_KEY environment variable.")
	}
	if resp.Diagnostics.HasError() {
		return
	}
	c, err := client.New(client.Config{URL: url, APIKey: apiKey, Insecure: insecure, UserAgent: "terraform-provider-airlock/" + p.version, Timeout: time.Duration(timeout) * time.Second})
	if err != nil {
		resp.Diagnostics.AddError("Unable to create Airlock client", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}
func (p *AirlockProvider) Resources(context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewApplicationResource, NewApplicationCategoryResource, NewBaselineResource, NewBlocklistResource, NewGroupResource,
		NewGroupApplicationPolicyResource, NewGroupBaselinePolicyResource, NewGroupBlocklistPolicyResource, NewGroupPathResource, NewGroupProcessResource, NewGroupPublisherResource,
	}
}
func (p *AirlockProvider) DataSources(context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewApplicationsDataSource, NewApplicationCategoriesDataSource, NewBaselinesDataSource, NewBlocklistsDataSource, NewGroupsDataSource, NewAgentsDataSource,
	}
}
func (p *AirlockProvider) Functions(context.Context) []func() function.Function { return nil }
func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
