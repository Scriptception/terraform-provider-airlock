package provider

import (
	"context"
	"os"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"
)

var protoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"airlock": providerserver.NewProtocol6WithError(New("test")()),
}

func testAccPreCheck(t *testing.T) {
	t.Helper()
	if os.Getenv("TF_ACC") == "" {
		t.Skip("TF_ACC not set; skipping acceptance test")
	}
	for _, v := range []string{"AIRLOCK_URL", "AIRLOCK_API_KEY"} {
		if os.Getenv(v) == "" {
			t.Fatalf("acceptance test requires %s to be set", v)
		}
	}
}

func TestProviderSchema(t *testing.T) {
	server, err := protoV6ProviderFactories["airlock"]()
	if err != nil {
		t.Fatal(err)
	}
	resp, err := server.GetProviderSchema(context.Background(), &tfprotov6.GetProviderSchemaRequest{})
	if err != nil {
		t.Fatal(err)
	}
	for _, diagnostic := range resp.Diagnostics {
		if diagnostic.Severity == tfprotov6.DiagnosticSeverityError {
			t.Fatalf("provider schema error: %s: %s", diagnostic.Summary, diagnostic.Detail)
		}
	}
	if _, ok := resp.DataSourceSchemas["airlock_cloud_groups"]; !ok {
		t.Fatal("provider schema does not register airlock_cloud_groups")
	}
}
