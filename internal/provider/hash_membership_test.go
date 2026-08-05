package provider

import (
	"context"
	"fmt"
	"reflect"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

const (
	hashA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	hashB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	hashC = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
)

func TestExtractSHA256sFromPackageXML(t *testing.T) {
	raw := []byte(`<AirlockCapture>
		<filewrite sha256="` + hashB + `">
			<sha256>` + hashA + `</sha256>
			<sha512>` + hashC + hashC + `</sha512>
		</filewrite>
		<fileload><sha256>` + hashA + `</sha256></fileload>
	</AirlockCapture>`)

	got := extractSHA256s(raw)
	want := []string{hashA, hashB}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected hashes: got %#v want %#v", got, want)
	}
}

func TestExtractSHA256sIgnoresMetaruleCriteriaValues(t *testing.T) {
	raw := []byte(`<AirlockCapture>
		<filewrite sha256="` + hashA + `" />
		<criteria field="sha256" operation="match" value="` + hashB + `" />
	</AirlockCapture>`)
	if got, want := extractSHA256s(raw), []string{hashA}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected hashes: got %#v want %#v", got, want)
	}
}

func TestParseHashMembershipImportID(t *testing.T) {
	targetID, hashes, id, err := parseHashMembershipImportID("application", "application:1700000000:"+hashB+","+hashA)
	if err != nil {
		t.Fatal(err)
	}
	if targetID != "1700000000" {
		t.Fatalf("unexpected target ID: %s", targetID)
	}
	if want := []string{hashA, hashB}; !reflect.DeepEqual(hashes, want) {
		t.Fatalf("unexpected hashes: got %#v want %#v", hashes, want)
	}
	if want := "application:1700000000:" + hashA + "," + hashB; id != want {
		t.Fatalf("unexpected normalized ID: got %q want %q", id, want)
	}
}

func TestParseHashMembershipImportIDRejectsWrongKind(t *testing.T) {
	_, _, _, err := parseHashMembershipImportID("baseline", "application:1700000000:"+hashA)
	if err == nil {
		t.Fatal("expected kind mismatch error")
	}
}

func TestHashesSubsetNormalizesInput(t *testing.T) {
	if !hashesSubset([]string{hashA, hashB}, []string{hashB, stringsToUpper(hashA)}) {
		t.Fatal("expected hashes to match case-insensitively")
	}
	if hashesSubset([]string{hashA}, []string{hashA, hashB}) {
		t.Fatal("expected missing hash to fail subset check")
	}
}

func TestHashSetDiffIsAuthoritative(t *testing.T) {
	add, remove := hashSetDiff([]string{hashA, hashB}, []string{hashB, hashC})
	if !reflect.DeepEqual(add, []string{hashC}) || !reflect.DeepEqual(remove, []string{hashA}) {
		t.Fatalf("unexpected diff: add=%#v remove=%#v", add, remove)
	}
}

func TestHashBatches(t *testing.T) {
	hashes := make([]string, 501)
	for i := range hashes {
		hashes[i] = fmt.Sprintf("%064x", i)
	}
	batches := hashBatches(hashes, hashMutationBatchSize)
	if len(batches) != 3 || len(batches[0]) != 250 || len(batches[1]) != 250 || len(batches[2]) != 1 {
		t.Fatalf("unexpected batches: %#v", []int{len(batches[0]), len(batches[1]), len(batches[2])})
	}
}

func TestParseAuthoritativeHashMembershipImportID(t *testing.T) {
	targetID, err := parseAuthoritativeHashMembershipImportID("application", "application:1700000000")
	if err != nil {
		t.Fatal(err)
	}
	if targetID != "1700000000" {
		t.Fatalf("target ID = %q, want 1700000000", targetID)
	}
	if _, err := parseAuthoritativeHashMembershipImportID("application", "application:1700000000:"+hashA); err == nil {
		t.Fatal("legacy three-part import ID was accepted")
	}
}

func TestLegacyAuthoritativeHashChunksFailClosed(t *testing.T) {
	ctx := context.Background()
	for _, kind := range []string{"application", "blocklist"} {
		t.Run(kind, func(t *testing.T) {
			r := &hashMembershipResource{kind: kind}
			var schemaResp resource.SchemaResponse
			r.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

			for chunkNumber, hash := range []string{hashA, hashB} {
				model := hashMembershipModel{
					ID:       types.StringValue(kind + ":package-1:" + hash),
					TargetID: types.StringValue("package-1"),
					Hashes:   types.SetValueMust(types.StringType, []attr.Value{types.StringValue(hash)}),
				}
				state := tfsdk.State{Schema: schemaResp.Schema}
				if diags := state.Set(ctx, &model); diags.HasError() {
					t.Fatalf("chunk %d state: %v", chunkNumber+1, diags)
				}
				plan := tfsdk.Plan{Schema: schemaResp.Schema}
				if diags := plan.Set(ctx, &model); diags.HasError() {
					t.Fatalf("chunk %d plan: %v", chunkNumber+1, diags)
				}

				readResp := &resource.ReadResponse{State: state}
				r.Read(ctx, resource.ReadRequest{State: state}, readResp)
				if !readResp.Diagnostics.HasError() {
					t.Fatalf("chunk %d read did not fail closed", chunkNumber+1)
				}

				updateResp := &resource.UpdateResponse{State: state}
				r.Update(ctx, resource.UpdateRequest{Plan: plan, State: state}, updateResp)
				if !updateResp.Diagnostics.HasError() {
					t.Fatalf("chunk %d update did not fail closed", chunkNumber+1)
				}

				deleteResp := &resource.DeleteResponse{State: state}
				r.Delete(ctx, resource.DeleteRequest{State: state}, deleteResp)
				if !deleteResp.Diagnostics.HasError() {
					t.Fatalf("chunk %d delete did not fail closed", chunkNumber+1)
				}
			}
		})
	}
}

func stringsToUpper(in string) string {
	out := []byte(in)
	for i, b := range out {
		if b >= 'a' && b <= 'z' {
			out[i] = b - 'a' + 'A'
		}
	}
	return string(out)
}
