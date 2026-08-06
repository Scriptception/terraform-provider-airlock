package provider

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

func TestMetaruleTypedCriteriaSchemaUpdatesInPlace(t *testing.T) {
	ctx := context.Background()
	resourceImpl := &metaruleResource{kind: applicationMetarule}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	priorCriteria := criteriaListValue([]metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Example Publisher"}})
	desiredCriteria := criteriaListValue([]metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}})
	prior := metarulePlanTestModel(priorCriteria, types.StringNull())
	desired := metarulePlanTestModel(desiredCriteria, types.StringNull())
	desired.ID = types.StringUnknown()

	configState := tfsdk.State{Schema: schemaResp.Schema}
	state := tfsdk.State{Schema: schemaResp.Schema}
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := configState.Set(ctx, &desired); diags.HasError() {
		t.Fatalf("set config: %v", diags)
	}
	if diags := state.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set state: %v", diags)
	}
	if diags := plan.Set(ctx, &desired); diags.HasError() {
		t.Fatalf("set plan: %v", diags)
	}

	criteriaAttribute := schemaResp.Schema.Attributes["criteria"].(schema.ListNestedAttribute)
	listReq := planmodifier.ListRequest{
		Path:        pathRoot("criteria"),
		Config:      tfsdk.Config{Schema: schemaResp.Schema, Raw: configState.Raw},
		ConfigValue: desiredCriteria,
		Plan:        plan,
		PlanValue:   desiredCriteria,
		State:       state,
		StateValue:  priorCriteria,
	}
	listResp := &planmodifier.ListResponse{PlanValue: desiredCriteria}
	for _, modifier := range criteriaAttribute.PlanModifiers {
		listReq.PlanValue = listResp.PlanValue
		modifier.PlanModifyList(ctx, listReq, listResp)
	}
	if listResp.Diagnostics.HasError() {
		t.Fatalf("typed criteria diagnostics: %v", listResp.Diagnostics)
	}
	if listResp.RequiresReplace {
		t.Fatal("typed criteria change unexpectedly requires replacement")
	}

	legacyAttribute := schemaResp.Schema.Attributes["criteria_json"].(schema.StringAttribute)
	legacyReq := planmodifier.StringRequest{
		Path:        pathRoot("criteria_json"),
		Config:      tfsdk.Config{Schema: schemaResp.Schema, Raw: configState.Raw},
		ConfigValue: types.StringValue(`[{"field":"publisher","operation":"contains","value":"Example Publisher"}]`),
		Plan:        plan,
		PlanValue:   types.StringValue(`[{"field":"publisher","operation":"contains","value":"Example Publisher"}]`),
		State:       state,
		StateValue:  types.StringValue(`[{"field":"publisher","operation":"match","value":"Example Publisher"}]`),
	}
	legacyResp := &planmodifier.StringResponse{PlanValue: legacyReq.PlanValue}
	for _, modifier := range legacyAttribute.PlanModifiers {
		modifier.PlanModifyString(ctx, legacyReq, legacyResp)
	}
	if legacyResp.Diagnostics.HasError() {
		t.Fatalf("legacy criteria diagnostics: %v", legacyResp.Diagnostics)
	}
	if !legacyResp.RequiresReplace {
		t.Fatal("legacy criteria_json change must continue to require replacement")
	}
}

func TestMetaruleModifyPlanRejectsKnownMultiMutationChanges(t *testing.T) {
	base := metaruleCriterion{Field: "publisher", Operation: "match", Value: "Example Publisher"}
	path := metaruleCriterion{Field: "path", Operation: "wildcard", Value: "/opt/example/*"}
	tests := []struct {
		name        string
		prior       []metaruleCriterion
		desired     []metaruleCriterion
		desiredName string
	}{
		{
			name:    "update and add",
			prior:   []metaruleCriterion{base},
			desired: []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}, path},
		},
		{
			name:        "name and criteria",
			prior:       []metaruleCriterion{base},
			desired:     []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}},
			desiredName: "Renamed Example",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prior := metarulePlanTestModel(criteriaListValue(test.prior), types.StringNull())
			plan := metarulePlanTestModel(criteriaListValue(test.desired), types.StringNull())
			if test.desiredName != "" {
				plan.Name = types.StringValue(test.desiredName)
			}
			diagnostics := runMetaruleModifyPlan(t, prior, plan)
			if !diagnostics.HasError() || !strings.Contains(diagnostics.Errors()[0].Summary(), "requires multiple Airlock mutations") {
				t.Fatalf("plan diagnostics: %v", diagnostics)
			}
		})
	}
}

func TestMetaruleModifyPlanAcceptsKnownSingleMutationChanges(t *testing.T) {
	base := metaruleCriterion{Field: "publisher", Operation: "match", Value: "Example Publisher"}
	path := metaruleCriterion{Field: "path", Operation: "wildcard", Value: "/opt/example/*"}
	tests := []struct {
		name        string
		prior       []metaruleCriterion
		desired     []metaruleCriterion
		desiredName string
	}{
		{
			name:    "one criterion update",
			prior:   []metaruleCriterion{base},
			desired: []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}},
		},
		{name: "one criterion add", prior: []metaruleCriterion{base}, desired: []metaruleCriterion{base, path}},
		{name: "name only", prior: []metaruleCriterion{base}, desired: []metaruleCriterion{base}, desiredName: "Renamed Example"},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prior := metarulePlanTestModel(criteriaListValue(test.prior), types.StringNull())
			plan := metarulePlanTestModel(criteriaListValue(test.desired), types.StringNull())
			if test.desiredName != "" {
				plan.Name = types.StringValue(test.desiredName)
			}
			if diagnostics := runMetaruleModifyPlan(t, prior, plan); diagnostics.HasError() {
				t.Fatalf("single-mutation plan diagnostics: %v", diagnostics)
			}
		})
	}
}

func TestMetaruleModifyPlanSkipsNonUpdateAndIndeterminatePlans(t *testing.T) {
	criteria := []metaruleCriterion{
		{Field: "publisher", Operation: "match", Value: "Example Publisher"},
		{Field: "path", Operation: "wildcard", Value: "/opt/example/*"},
		{Field: "hostname", Operation: "wildcard", Value: "EXAMPLE-*"},
	}
	prior := metarulePlanTestModel(criteriaListValue(criteria[:1]), types.StringNull())
	multiPlan := metarulePlanTestModel(criteriaListValue(criteria), types.StringNull())

	t.Run("create", func(t *testing.T) {
		if diagnostics := runMetaruleModifyPlanWithNull(t, prior, multiPlan, true, false); diagnostics.HasError() {
			t.Fatalf("create plan diagnostics: %v", diagnostics)
		}
	})
	t.Run("destroy", func(t *testing.T) {
		if diagnostics := runMetaruleModifyPlanWithNull(t, prior, multiPlan, false, true); diagnostics.HasError() {
			t.Fatalf("destroy plan diagnostics: %v", diagnostics)
		}
	})
	t.Run("unknown criteria", func(t *testing.T) {
		unknownPlan := multiPlan
		unknownPlan.Criteria = types.ListUnknown(metaruleCriterionObjectType)
		if diagnostics := runMetaruleModifyPlan(t, prior, unknownPlan); diagnostics.HasError() {
			t.Fatalf("unknown plan diagnostics: %v", diagnostics)
		}
	})
	t.Run("incomplete imported state", func(t *testing.T) {
		imported := prior
		imported.Name = types.StringNull()
		imported.OS = types.StringNull()
		imported.Criteria = types.ListNull(metaruleCriterionObjectType)
		if diagnostics := runMetaruleModifyPlan(t, imported, multiPlan); diagnostics.HasError() {
			t.Fatalf("import plan diagnostics: %v", diagnostics)
		}
	})
	t.Run("replacement", func(t *testing.T) {
		replacementPlan := multiPlan
		replacementPlan.PackageID = types.StringValue("package-2")
		if diagnostics := runMetaruleModifyPlan(t, prior, replacementPlan); diagnostics.HasError() {
			t.Fatalf("replacement plan diagnostics: %v", diagnostics)
		}
	})
}

func TestMetaruleCriteriaNoOpPerformsNoRequestsAndPreservesID(t *testing.T) {
	criteria := []metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Example Publisher"}}
	harness := newMetaruleAPIHarness(t, applicationMetarule, liveCriteria(criteria))
	defer harness.Close()

	got, diagnostics := runMetaruleUpdate(t, harness, criteria, criteria)
	if diagnostics.HasError() {
		t.Fatalf("no-op diagnostics: %v", diagnostics)
	}
	if len(harness.requests) != 0 {
		t.Fatalf("no-op made requests: %#v", harness.requests)
	}
	if got.ID.ValueString() != "rule-1" {
		t.Fatalf("metarule ID = %q, want rule-1", got.ID.ValueString())
	}
}

func TestMetaruleCriteriaUpdatesSharedPositionsInPlace(t *testing.T) {
	for _, kind := range []metaruleKind{applicationMetarule, blocklistMetarule} {
		t.Run(string(kind), func(t *testing.T) {
			prior := []metaruleCriterion{
				{Field: "publisher", Operation: "match", Value: "Example Publisher"},
				{Field: "path", Operation: "wildcard", Value: "/opt/example/*"},
			}
			desired := append([]metaruleCriterion(nil), prior...)
			desired[1] = metaruleCriterion{Field: "path", Operation: "contains", Value: "/srv/example/"}
			harness := newMetaruleAPIHarness(t, kind, liveCriteria(prior))
			defer harness.Close()

			got, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
			if diagnostics.HasError() {
				t.Fatalf("update diagnostics: %v", diagnostics)
			}
			prefix := "/v1/" + string(kind) + "/metarule"
			wantPaths := []string{prefix, prefix + "/criteria/update", prefix}
			assertMetaruleRequestPaths(t, harness.requests, wantPaths)
			assertRequestBody(t, harness.requests[1].body, map[string]any{
				"criteriaid": "criterion-2",
				"field":      "path",
				"operation":  "contains",
				"value":      "/srv/example/",
			})
			if harness.criteria[0].ID != "criterion-1" || harness.criteria[1].ID != "criterion-2" {
				t.Fatalf("shared criteria IDs changed: %#v", harness.criteria)
			}
			if got.ID.ValueString() != "rule-1" {
				t.Fatalf("metarule ID = %q, want rule-1", got.ID.ValueString())
			}
		})
	}
}

func TestMetaruleCriteriaAppendsOneCriterion(t *testing.T) {
	prior := []metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Example Publisher"}}
	desired := []metaruleCriterion{
		prior[0],
		{Field: "path", Operation: "wildcard", Value: "/opt/example/*"},
	}
	harness := newMetaruleAPIHarness(t, applicationMetarule, liveCriteria(prior))
	defer harness.Close()

	_, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
	if diagnostics.HasError() {
		t.Fatalf("addition diagnostics: %v", diagnostics)
	}
	wantPaths := []string{
		"/v1/application/metarule",
		"/v1/application/metarule/criteria/add",
		"/v1/application/metarule",
	}
	assertMetaruleRequestPaths(t, harness.requests, wantPaths)
	assertRequestBody(t, harness.requests[1].body, map[string]any{
		"metaruleid": "rule-1", "field": "path", "operation": "wildcard", "value": "/opt/example/*",
	})
	if !metaruleCriteriaEqual(criteriaFromLive(harness.criteria), desired) {
		t.Fatalf("live criteria = %#v, want %#v", harness.criteria, desired)
	}
}

func TestMetaruleCriteriaDeletesOneCriterion(t *testing.T) {
	prior := []metaruleCriterion{
		{Field: "publisher", Operation: "match", Value: "Example Publisher"},
		{Field: "path", Operation: "wildcard", Value: "/opt/example/*"},
	}
	desired := prior[:1]
	harness := newMetaruleAPIHarness(t, blocklistMetarule, liveCriteria(prior))
	defer harness.Close()

	_, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
	if diagnostics.HasError() {
		t.Fatalf("deletion diagnostics: %v", diagnostics)
	}
	wantPaths := []string{
		"/v1/blocklist/metarule",
		"/v1/blocklist/metarule/criteria/delete",
		"/v1/blocklist/metarule",
	}
	assertMetaruleRequestPaths(t, harness.requests, wantPaths)
	assertRequestBody(t, harness.requests[1].body, map[string]any{"criteriaid": "criterion-2"})
}

func TestMetaruleRejectsMultiMutationPlansBeforeAnyRequest(t *testing.T) {
	base := metaruleCriterion{Field: "publisher", Operation: "match", Value: "Example Publisher"}
	path := metaruleCriterion{Field: "path", Operation: "wildcard", Value: "/opt/example/*"}
	hostname := metaruleCriterion{Field: "hostname", Operation: "wildcard", Value: "EXAMPLE-*"}
	tests := []struct {
		name        string
		kind        metaruleKind
		prior       []metaruleCriterion
		desired     []metaruleCriterion
		priorName   string
		desiredName string
		wantCalls   string
	}{
		{
			name: "update and add", kind: applicationMetarule,
			prior: []metaruleCriterion{base},
			desired: []metaruleCriterion{
				{Field: "publisher", Operation: "contains", Value: "Example Publisher"},
				path,
			},
			wantCalls: "2 mutation calls",
		},
		{
			name: "multiple adds", kind: applicationMetarule,
			prior:     []metaruleCriterion{base},
			desired:   []metaruleCriterion{base, path, hostname},
			wantCalls: "2 mutation calls",
		},
		{
			name: "multiple deletes", kind: blocklistMetarule,
			prior:     []metaruleCriterion{base, path, hostname},
			desired:   []metaruleCriterion{base},
			wantCalls: "2 mutation calls",
		},
		{
			name: "name and criteria", kind: blocklistMetarule,
			prior:       []metaruleCriterion{base},
			desired:     []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}},
			priorName:   "Example",
			desiredName: "Renamed Example",
			wantCalls:   "2 mutation calls",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			harness := newMetaruleAPIHarness(t, test.kind, liveCriteria(test.prior))
			defer harness.Close()
			priorName := test.priorName
			if priorName == "" {
				priorName = "Example"
			}
			desiredName := test.desiredName
			if desiredName == "" {
				desiredName = priorName
			}

			_, diagnostics := runMetaruleUpdateWithNames(t, harness, test.prior, test.desired, priorName, desiredName)
			if !diagnostics.HasError() {
				t.Fatal("expected a multi-mutation plan to be rejected")
			}
			if !strings.Contains(diagnostics.Errors()[0].Summary(), "requires multiple Airlock mutations") ||
				!strings.Contains(diagnostics.Errors()[0].Detail(), test.wantCalls) {
				t.Fatalf("multi-mutation diagnostics: %v", diagnostics)
			}
			if len(harness.requests) != 0 {
				t.Fatalf("rejected plan made API requests: %#v", harness.requests)
			}
		})
	}
}

func TestMetaruleCriteriaUpdateFailsBeforeMutationOnLiveRace(t *testing.T) {
	prior := []metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Example Publisher"}}
	desired := []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}}
	live := []metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Changed Outside Terraform"}}
	harness := newMetaruleAPIHarness(t, applicationMetarule, liveCriteria(live))
	defer harness.Close()

	_, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
	if !diagnostics.HasError() || !strings.Contains(diagnostics.Errors()[0].Summary(), "changed outside Terraform") {
		t.Fatalf("race diagnostics: %v", diagnostics)
	}
	assertMetaruleRequestPaths(t, harness.requests, []string{"/v1/application/metarule"})
}

func TestMetaruleCriteriaUpdateReportsMutationAndReadbackFailures(t *testing.T) {
	prior := []metaruleCriterion{{Field: "publisher", Operation: "match", Value: "Example Publisher"}}
	desired := []metaruleCriterion{{Field: "publisher", Operation: "contains", Value: "Example Publisher"}}

	t.Run("mutation", func(t *testing.T) {
		harness := newMetaruleAPIHarness(t, applicationMetarule, liveCriteria(prior))
		defer harness.Close()
		harness.failPath = "/v1/application/metarule/criteria/update"
		_, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
		if !diagnostics.HasError() || !strings.Contains(diagnostics.Errors()[0].Summary(), "Unable to update Airlock metarule criteria") {
			t.Fatalf("mutation diagnostics: %v", diagnostics)
		}
		assertMetaruleRequestPaths(t, harness.requests, []string{
			"/v1/application/metarule",
			"/v1/application/metarule/criteria/update",
		})
	})

	t.Run("readback", func(t *testing.T) {
		harness := newMetaruleAPIHarness(t, applicationMetarule, liveCriteria(prior))
		defer harness.Close()
		harness.ignoreMutations = true
		_, diagnostics := runMetaruleUpdate(t, harness, prior, desired)
		if !diagnostics.HasError() || !strings.Contains(diagnostics.Errors()[0].Summary(), "verification failed") {
			t.Fatalf("readback diagnostics: %v", diagnostics)
		}
		assertMetaruleRequestPaths(t, harness.requests, []string{
			"/v1/application/metarule",
			"/v1/application/metarule/criteria/update",
			"/v1/application/metarule",
		})
	})
}

func TestDecodeLiveMetaruleCriteriaRejectsUnsafeIdentityAndOrder(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "missing ID", raw: `[{"index":0,"field":"publisher","operation":"match","value":"Example"}]`},
		{name: "missing index", raw: `[{"criteriaid":"criterion-1","field":"publisher","operation":"match","value":"Example"}]`},
		{name: "duplicate ID", raw: `[{"criteriaid":"criterion-1","index":0,"field":"publisher","operation":"match","value":"Example"},{"criteriaid":"criterion-1","index":1,"field":"path","operation":"wildcard","value":"/opt/*"}]`},
		{name: "non-contiguous index", raw: `[{"criteriaid":"criterion-1","index":0,"field":"publisher","operation":"match","value":"Example"},{"criteriaid":"criterion-2","index":2,"field":"path","operation":"wildcard","value":"/opt/*"}]`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := decodeLiveMetaruleCriteria([]byte(test.raw)); err == nil {
				t.Fatal("expected unsafe live criteria metadata to be rejected")
			}
		})
	}
}

type metaruleAPIRequest struct {
	path string
	body map[string]any
}

type metaruleAPIHarness struct {
	t               *testing.T
	kind            metaruleKind
	server          *httptest.Server
	criteria        []liveMetaruleCriterion
	requests        []metaruleAPIRequest
	failPath        string
	ignoreMutations bool
	additions       int
}

func newMetaruleAPIHarness(t *testing.T, kind metaruleKind, criteria []liveMetaruleCriterion) *metaruleAPIHarness {
	t.Helper()
	harness := &metaruleAPIHarness{t: t, kind: kind, criteria: criteria}
	harness.server = httptest.NewServer(http.HandlerFunc(harness.handle))
	return harness
}

func (h *metaruleAPIHarness) Close() {
	h.server.Close()
}

func (h *metaruleAPIHarness) handle(w http.ResponseWriter, r *http.Request) {
	h.t.Helper()
	if r.Method != http.MethodPost {
		h.t.Fatalf("method = %q, want POST", r.Method)
	}
	prefix := "/v1/" + string(h.kind) + "/metarule"
	var body map[string]any
	if r.Body != nil {
		decoder := json.NewDecoder(r.Body)
		if err := decoder.Decode(&body); err != nil && err.Error() != "EOF" {
			h.t.Fatal(err)
		}
	}
	h.requests = append(h.requests, metaruleAPIRequest{path: r.URL.Path, body: body})
	if r.URL.Path == h.failPath {
		w.WriteHeader(http.StatusInternalServerError)
		_, _ = w.Write([]byte(`{"error":"failed"}`))
		return
	}

	switch r.URL.Path {
	case prefix:
		h.assertListContract(r, body)
		h.writeListResponse(w)
	case prefix + "/criteria/update":
		if h.ignoreMutations {
			h.writeSuccess(w)
			return
		}
		id := body["criteriaid"].(string)
		criterion := criterionFromBody(body)
		for index := range h.criteria {
			if h.criteria[index].ID == id {
				h.criteria[index].Criterion = criterion
				h.writeSuccess(w)
				return
			}
		}
		h.t.Fatalf("update referenced unknown criterion ID")
	case prefix + "/criteria/add":
		if h.ignoreMutations {
			h.writeSuccess(w)
			return
		}
		h.additions++
		h.criteria = append(h.criteria, liveMetaruleCriterion{
			ID:        fmt.Sprintf("criterion-added-%d", h.additions),
			Index:     len(h.criteria),
			Criterion: criterionFromBody(body),
		})
		h.writeSuccess(w)
	case prefix + "/criteria/delete":
		if h.ignoreMutations {
			h.writeSuccess(w)
			return
		}
		id := body["criteriaid"].(string)
		for index := range h.criteria {
			if h.criteria[index].ID != id {
				continue
			}
			h.criteria = append(h.criteria[:index], h.criteria[index+1:]...)
			for next := range h.criteria {
				h.criteria[next].Index = next
			}
			h.writeSuccess(w)
			return
		}
		h.t.Fatalf("delete referenced unknown criterion ID")
	default:
		h.t.Fatalf("unexpected path: %s", r.URL.Path)
	}
}

func (h *metaruleAPIHarness) assertListContract(r *http.Request, body map[string]any) {
	h.t.Helper()
	if h.kind == applicationMetarule {
		if body != nil {
			h.t.Fatalf("application metarule list unexpectedly used body: %#v", body)
		}
		if r.URL.Query().Get("applicationid") != "package-1" || r.URL.Query().Get("include_criteria") != "1" {
			h.t.Fatalf("application metarule list query = %q", r.URL.RawQuery)
		}
		return
	}
	assertRequestBody(h.t, body, map[string]any{"blocklistid": "package-1", "include_criteria": true})
}

func (h *metaruleAPIHarness) writeListResponse(w http.ResponseWriter) {
	h.t.Helper()
	criteria := make([]map[string]any, 0, len(h.criteria))
	for _, live := range h.criteria {
		criteria = append(criteria, map[string]any{
			"criteriaid": live.ID,
			"index":      live.Index,
			"field":      live.Criterion.Field,
			"operation":  live.Criterion.Operation,
			"value":      live.Criterion.Value,
		})
	}
	response := map[string]any{
		"error": "Success",
		"response": map[string]any{"metarules": []map[string]any{{
			"metaruleid": "rule-1",
			"name":       "Example",
			"os":         "windows",
			"criteria":   criteria,
		}}},
	}
	if err := json.NewEncoder(w).Encode(response); err != nil {
		h.t.Fatal(err)
	}
}

func (h *metaruleAPIHarness) writeSuccess(w http.ResponseWriter) {
	h.t.Helper()
	_, _ = w.Write([]byte(`{"error":"Success"}`))
}

func runMetaruleUpdate(t *testing.T, harness *metaruleAPIHarness, priorCriteria, desiredCriteria []metaruleCriterion) (metaruleModel, diag.Diagnostics) {
	return runMetaruleUpdateWithNames(t, harness, priorCriteria, desiredCriteria, "Example", "Example")
}

func runMetaruleUpdateWithNames(t *testing.T, harness *metaruleAPIHarness, priorCriteria, desiredCriteria []metaruleCriterion, priorName, desiredName string) (metaruleModel, diag.Diagnostics) {
	t.Helper()
	ctx := context.Background()
	apiClient, err := client.New(client.Config{URL: harness.server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	resourceImpl := &metaruleResource{configuredResource: configuredResource{client: apiClient}, kind: harness.kind}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	prior := metarulePlanTestModel(criteriaListValue(priorCriteria), types.StringNull())
	planModel := metarulePlanTestModel(criteriaListValue(desiredCriteria), types.StringNull())
	prior.Name = types.StringValue(priorName)
	planModel.Name = types.StringValue(desiredName)
	planModel.ID = types.StringUnknown()
	state := tfsdk.State{Schema: schemaResp.Schema}
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if diags := state.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set state: %v", diags)
	}
	if diags := plan.Set(ctx, &planModel); diags.HasError() {
		t.Fatalf("set plan: %v", diags)
	}
	resp := &resource.UpdateResponse{State: tfsdk.State{Schema: schemaResp.Schema}}
	resourceImpl.Update(ctx, resource.UpdateRequest{State: state, Plan: plan}, resp)
	if resp.Diagnostics.HasError() {
		return metaruleModel{}, resp.Diagnostics
	}
	var got metaruleModel
	if diags := resp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("get state: %v", diags)
	}
	return got, resp.Diagnostics
}

func runMetaruleModifyPlan(t *testing.T, prior, planned metaruleModel) diag.Diagnostics {
	return runMetaruleModifyPlanWithNull(t, prior, planned, false, false)
}

func runMetaruleModifyPlanWithNull(t *testing.T, prior, planned metaruleModel, nullState, nullPlan bool) diag.Diagnostics {
	t.Helper()
	ctx := context.Background()
	resourceImpl := &metaruleResource{kind: applicationMetarule}
	var schemaResp resource.SchemaResponse
	resourceImpl.Schema(ctx, resource.SchemaRequest{}, &schemaResp)

	state := tfsdk.State{Schema: schemaResp.Schema}
	plan := tfsdk.Plan{Schema: schemaResp.Schema}
	if nullState {
		state.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)
	} else if diags := state.Set(ctx, &prior); diags.HasError() {
		t.Fatalf("set plan-modifier state: %v", diags)
	}
	if nullPlan {
		plan.Raw = tftypes.NewValue(schemaResp.Schema.Type().TerraformType(ctx), nil)
	} else if diags := plan.Set(ctx, &planned); diags.HasError() {
		t.Fatalf("set plan-modifier plan: %v", diags)
	}

	resp := &resource.ModifyPlanResponse{Plan: plan}
	resourceImpl.ModifyPlan(ctx, resource.ModifyPlanRequest{State: state, Plan: plan}, resp)
	return resp.Diagnostics
}

func liveCriteria(criteria []metaruleCriterion) []liveMetaruleCriterion {
	live := make([]liveMetaruleCriterion, 0, len(criteria))
	for index, criterion := range criteria {
		live = append(live, liveMetaruleCriterion{
			ID:        fmt.Sprintf("criterion-%d", index+1),
			Index:     index,
			Criterion: criterion,
		})
	}
	return live
}

func criteriaFromLive(live []liveMetaruleCriterion) []metaruleCriterion {
	criteria := make([]metaruleCriterion, 0, len(live))
	for _, item := range live {
		criteria = append(criteria, item.Criterion)
	}
	return criteria
}

func criterionFromBody(body map[string]any) metaruleCriterion {
	return metaruleCriterion{
		Field:     body["field"].(string),
		Operation: body["operation"].(string),
		Value:     body["value"].(string),
	}
}

func assertMetaruleRequestPaths(t *testing.T, requests []metaruleAPIRequest, want []string) {
	t.Helper()
	if len(requests) != len(want) {
		t.Fatalf("request count = %d, want %d: %#v", len(requests), len(want), requests)
	}
	for index := range want {
		if requests[index].path != want[index] {
			t.Fatalf("request %d path = %q, want %q", index, requests[index].path, want[index])
		}
	}
}

func assertRequestBody(t *testing.T, got, want map[string]any) {
	t.Helper()
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	if string(gotJSON) != string(wantJSON) {
		t.Fatalf("body = %s, want %s", gotJSON, wantJSON)
	}
}
