package provider

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

type urlValidator struct{}

func (urlValidator) Description(context.Context) string {
	return "must be an absolute HTTP or HTTPS URL"
}
func (v urlValidator) MarkdownDescription(ctx context.Context) string { return v.Description(ctx) }
func (urlValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	u, err := url.Parse(req.ConfigValue.ValueString())
	if err != nil || u.Scheme == "" || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid Airlock URL", "The URL must be absolute and use http or https.")
	}
}

type positiveInt64Validator struct{}

func (positiveInt64Validator) Description(context.Context) string { return "must be greater than zero" }
func (v positiveInt64Validator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (positiveInt64Validator) ValidateInt64(_ context.Context, req validator.Int64Request, resp *validator.Int64Response) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	if req.ConfigValue.ValueInt64() <= 0 {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid timeout", "The timeout must be greater than zero seconds.")
	}
}

type stringOneOfValidator struct{ allowed []string }

func (v stringOneOfValidator) Description(context.Context) string {
	return fmt.Sprintf("must be one of: %s", strings.Join(v.allowed, ", "))
}
func (v stringOneOfValidator) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}
func (v stringOneOfValidator) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	got := req.ConfigValue.ValueString()
	for _, allowed := range v.allowed {
		if got == allowed {
			return
		}
	}
	resp.Diagnostics.AddAttributeError(req.Path, "Invalid value", v.Description(context.Background())+".")
}
