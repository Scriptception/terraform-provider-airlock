package provider

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

func TestAccReadOnlyDataSources_basic(t *testing.T) {
	resource.Test(t, resource.TestCase{
		PreCheck:                 func() { testAccPreCheck(t) },
		ProtoV6ProviderFactories: protoV6ProviderFactories,
		Steps: []resource.TestStep{
			{
				Config: `
provider "airlock" {}

data "airlock_groups" "all" {}
data "airlock_applications" "all" {}
data "airlock_baselines" "all" {}
data "airlock_blocklists" "all" {}
`,
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet("data.airlock_groups.all", "items_json"),
					resource.TestCheckResourceAttrSet("data.airlock_applications.all", "items_json"),
					resource.TestCheckResourceAttrSet("data.airlock_baselines.all", "items_json"),
					resource.TestCheckResourceAttrSet("data.airlock_blocklists.all", "items_json"),
				),
			},
		},
	})
}
