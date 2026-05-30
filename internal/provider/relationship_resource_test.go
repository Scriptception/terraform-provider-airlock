package provider

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestRelationshipResourcesReadOnlySchemaAttributes(t *testing.T) {
	tests := []struct {
		name    string
		res     resourceWithRelationships
		attrs   map[string]any
		want    relModel
		missing []string
	}{
		{
			name:  "application policy",
			res:   NewGroupApplicationPolicyResource().(*relResource),
			attrs: map[string]any{"id": "g:a", "group_id": "g", "target_id": "a"},
			want:  relModel{ID: types.StringValue("g:a"), GroupID: types.StringValue("g"), TargetID: types.StringValue("a")},
		},
		{
			name:  "blocklist policy",
			res:   NewGroupBlocklistPolicyResource().(*relResource),
			attrs: map[string]any{"id": "g:b", "group_id": "g", "target_id": "b", "audit": true},
			want:  relModel{ID: types.StringValue("g:b"), GroupID: types.StringValue("g"), TargetID: types.StringValue("b"), Audit: types.BoolValue(true)},
		},
		{
			name:  "path",
			res:   NewGroupPathResource().(*relResource),
			attrs: map[string]any{"id": "g:C:\\Tools\\*", "group_id": "g", "value": "C:\\Tools\\*", "comment": "trusted"},
			want:  relModel{ID: types.StringValue("g:C:\\Tools\\*"), GroupID: types.StringValue("g"), Value: types.StringValue("C:\\Tools\\*"), Comment: types.StringValue("trusted")},
		},
		{
			name:  "process",
			res:   NewGroupProcessResource().(*relResource),
			attrs: map[string]any{"id": "g:pprocess:tool.exe", "group_id": "g", "type": "pprocess", "value": "tool.exe", "comment": "trusted"},
			want:  relModel{ID: types.StringValue("g:pprocess:tool.exe"), GroupID: types.StringValue("g"), Type: types.StringValue("pprocess"), Value: types.StringValue("tool.exe"), Comment: types.StringValue("trusted")},
		},
		{
			name:  "publisher",
			res:   NewGroupPublisherResource().(*relResource),
			attrs: map[string]any{"id": "g:Publisher", "group_id": "g", "value": "Publisher", "comment": "trusted"},
			want:  relModel{ID: types.StringValue("g:Publisher"), GroupID: types.StringValue("g"), Value: types.StringValue("Publisher"), Comment: types.StringValue("trusted")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, diags := tt.res.relFromAttributes(context.Background(), fakeAttrGetter(t, tt.attrs))
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			assertRelModel(t, got, tt.want)
		})
	}
}

type resourceWithRelationships interface {
	relFromAttributes(context.Context, attrGetter) (relModel, diag.Diagnostics)
}

func fakeAttrGetter(t *testing.T, attrs map[string]any) attrGetter {
	t.Helper()
	return func(_ context.Context, attrPath path.Path, target interface{}) diag.Diagnostics {
		name := attrPath.String()
		value, ok := attrs[name]
		if !ok {
			var diags diag.Diagnostics
			diags.AddError("unexpected attribute read", name)
			return diags
		}
		switch target := target.(type) {
		case *types.String:
			s, ok := value.(string)
			if !ok {
				t.Fatalf("%s value is %T, want string", name, value)
			}
			*target = types.StringValue(s)
		case *types.Bool:
			b, ok := value.(bool)
			if !ok {
				t.Fatalf("%s value is %T, want bool", name, value)
			}
			*target = types.BoolValue(b)
		default:
			t.Fatalf("unexpected target type %T", target)
		}
		return nil
	}
}

func assertRelModel(t *testing.T, got, want relModel) {
	t.Helper()
	if got.ID.ValueString() != want.ID.ValueString() ||
		got.GroupID.ValueString() != want.GroupID.ValueString() ||
		got.TargetID.ValueString() != want.TargetID.ValueString() ||
		got.Value.ValueString() != want.Value.ValueString() ||
		got.Type.ValueString() != want.Type.ValueString() ||
		got.Comment.ValueString() != want.Comment.ValueString() ||
		got.Audit.ValueBool() != want.Audit.ValueBool() {
		t.Fatalf("unexpected model:\n got: %#v\nwant: %#v", got, want)
	}
}
