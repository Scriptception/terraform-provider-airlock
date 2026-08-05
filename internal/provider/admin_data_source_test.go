package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

func TestCloudGroupsDataSourceReadsSensitiveRawInventory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if got := req.URL.Path; got != "/v1/cloudgroups" {
			t.Fatalf("unexpected path: %s", got)
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"cloudgroups":[]}}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}

	d := NewCloudGroupsDataSource().(*jsonDataSource)
	d.client = apiClient
	var schemaResp datasource.SchemaResponse
	d.Schema(context.Background(), datasource.SchemaRequest{}, &schemaResp)
	itemsAttribute, ok := schemaResp.Schema.Attributes["items_json"].(schema.StringAttribute)
	if !ok || !itemsAttribute.Sensitive {
		t.Fatal("items_json must be a sensitive string attribute")
	}

	config := tfsdk.Config{Schema: schemaResp.Schema}
	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(context.Background(), &struct {
		ItemsJSON types.String `tfsdk:"items_json"`
	}{ItemsJSON: types.StringNull()}); diags.HasError() {
		t.Fatalf("set initial state: %v", diags)
	}
	resp := &datasource.ReadResponse{State: state}
	d.Read(context.Background(), datasource.ReadRequest{Config: config}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("read diagnostics: %v", resp.Diagnostics)
	}

	var itemsJSON types.String
	resp.Diagnostics.Append(resp.State.GetAttribute(context.Background(), pathRoot("items_json"), &itemsJSON)...)
	if resp.Diagnostics.HasError() {
		t.Fatalf("state diagnostics: %v", resp.Diagnostics)
	}
	var out struct {
		CloudGroups []json.RawMessage `json:"cloudgroups"`
	}
	if err := json.Unmarshal([]byte(itemsJSON.ValueString()), &out); err != nil {
		t.Fatal(err)
	}
	if out.CloudGroups == nil || len(out.CloudGroups) != 0 {
		t.Fatalf("unexpected cloud groups state: %s", itemsJSON.ValueString())
	}
}
