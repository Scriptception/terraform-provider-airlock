package provider

import (
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

func testAccMutationPreCheck(t *testing.T) {
	t.Helper()
	testAccPreCheck(t)
	if os.Getenv("AIRLOCK_ACC_MUTATION") == "" {
		t.Skip("AIRLOCK_ACC_MUTATION not set; skipping mutation acceptance test")
	}
}

func TestAccResources_mutationLifecycle(t *testing.T) {
	suffix := time.Now().UTC().Format("20060102150405")
	config := fmt.Sprintf(`
provider "airlock" {}

resource "airlock_group" "example" {
  name   = "tf-acc-group-%[1]s"
  hidden = false
}

resource "airlock_application" "example" {
  name    = "tf-acc-application-%[1]s"
  version = "1"
}

resource "airlock_baseline" "example" {
  name = "tf-acc-baseline-%[1]s"
}

resource "airlock_blocklist" "example" {
  name = "tf-acc-blocklist-%[1]s"
}

resource "airlock_group_application_policy" "example" {
  group_id  = airlock_group.example.id
  target_id = airlock_application.example.id
}

resource "airlock_group_baseline_policy" "example" {
  group_id  = airlock_group.example.id
  target_id = airlock_baseline.example.id
}

resource "airlock_group_blocklist_policy" "example" {
  group_id  = airlock_group.example.id
  target_id = airlock_blocklist.example.id
  audit     = true
}

resource "airlock_group_path" "example" {
  group_id = airlock_group.example.id
  value    = "C:\\TerraformAcceptance\\%[1]s\\*"
  comment  = "Terraform acceptance test"
}

resource "airlock_group_process" "example" {
  group_id = airlock_group.example.id
  type     = "pprocess"
  value    = "tf-acc-%[1]s.exe"
  comment  = "Terraform acceptance test"
}

resource "airlock_group_publisher" "example" {
  group_id = airlock_group.example.id
  value    = "Terraform Acceptance %[1]s"
  comment  = "Terraform acceptance test"
}
`, suffix)

	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccMutationPreCheck(t) },
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: config,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("airlock_group.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_application.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_baseline.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_blocklist.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_application_policy.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_baseline_policy.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_blocklist_policy.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_path.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_process.example", "id"),
					resource.TestCheckResourceAttrSet("airlock_group_publisher.example", "id"),
				),
			},
			importStep("airlock_group.example", nil),
			importStep("airlock_application.example", nil),
			importStep("airlock_baseline.example", nil),
			importStep("airlock_blocklist.example", nil),
			importStep("airlock_group_application_policy.example", compositeImportID("airlock_group_application_policy.example", "group_id", "target_id")),
			importStep("airlock_group_baseline_policy.example", compositeImportID("airlock_group_baseline_policy.example", "group_id", "target_id")),
			{
				ResourceName:            "airlock_group_blocklist_policy.example",
				ImportState:             true,
				ImportStateVerify:       true,
				ImportStateIdFunc:       compositeImportID("airlock_group_blocklist_policy.example", "group_id", "target_id"),
				ImportStateVerifyIgnore: []string{"audit"},
			},
			importStep("airlock_group_path.example", compositeImportID("airlock_group_path.example", "group_id", "value")),
			importStep("airlock_group_process.example", compositeImportID("airlock_group_process.example", "group_id", "type", "value")),
			importStep("airlock_group_publisher.example", compositeImportID("airlock_group_publisher.example", "group_id", "value")),
		},
	})
}

func importStep(resourceName string, idFunc resource.ImportStateIdFunc) resource.TestStep {
	step := resource.TestStep{
		ResourceName:      resourceName,
		ImportState:       true,
		ImportStateVerify: true,
	}
	if idFunc != nil {
		step.ImportStateIdFunc = idFunc
	}
	return step
}

func compositeImportID(resourceName string, attrs ...string) resource.ImportStateIdFunc {
	return func(s *terraform.State) (string, error) {
		rs, ok := s.RootModule().Resources[resourceName]
		if !ok {
			return "", fmt.Errorf("resource %s not found in state", resourceName)
		}
		parts := make([]string, 0, len(attrs))
		for _, attr := range attrs {
			v := rs.Primary.Attributes[attr]
			if v == "" {
				return "", fmt.Errorf("resource %s missing attribute %s for import ID", resourceName, attr)
			}
			parts = append(parts, v)
		}
		out := parts[0]
		for _, part := range parts[1:] {
			out += ":" + part
		}
		return out, nil
	}
}
