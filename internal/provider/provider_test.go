package provider

import (
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
	p := New("test")()
	if p == nil {
		t.Fatal("provider is nil")
	}
}
