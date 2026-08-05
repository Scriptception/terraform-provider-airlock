package provider

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/Scriptception/terraform-provider-airlock/internal/client"
)

func TestAgentGroupAssignmentDeleteFailsWithoutFallback(t *testing.T) {
	r := &agentGroupAssignmentResource{}
	state := agentAssignmentTestState(t, r, agentGroupAssignmentModel{
		ID: types.StringValue("agent-1"), AgentID: types.StringValue("agent-1"),
		GroupID: types.StringValue("group-1"), DestroyFallbackGroupID: types.StringNull(),
	})
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("destroy without fallback did not fail closed")
	}
}

func TestAgentGroupAssignmentDeleteMovesAndVerifiesFallback(t *testing.T) {
	requests := 0
	moved := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		switch req.URL.Path {
		case "/v1/agent/move":
			moved = true
			_, _ = w.Write([]byte(`{"error":"Success"}`))
		case "/v1/agent/find":
			groupID := "group-1"
			if moved {
				groupID = "fallback-1"
			}
			_, _ = w.Write([]byte(`{"error":"Success","response":{"agents":[{"agentid":"agent-1","groupid":"` + groupID + `"}]}}`))
		default:
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	r := &agentGroupAssignmentResource{configuredResource: configuredResource{client: apiClient}}
	state := agentAssignmentTestState(t, r, agentGroupAssignmentModel{
		ID: types.StringValue("agent-1"), AgentID: types.StringValue("agent-1"),
		GroupID: types.StringValue("group-1"), DestroyFallbackGroupID: types.StringValue("fallback-1"),
	})
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete diagnostics: %v", resp.Diagnostics)
	}
	if requests != 3 {
		t.Fatalf("requests = %d, want initial read, move, and verification", requests)
	}
}

func TestAgentGroupAssignmentDeleteAlreadyAtFallback(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.URL.Path != "/v1/agent/find" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"agents":[{"agentid":"agent-1","groupid":"fallback-1"}]}}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	r := &agentGroupAssignmentResource{configuredResource: configuredResource{client: apiClient}}
	state := agentAssignmentTestState(t, r, agentGroupAssignmentModel{
		ID: types.StringValue("agent-1"), AgentID: types.StringValue("agent-1"),
		GroupID: types.StringValue("group-1"), DestroyFallbackGroupID: types.StringValue("fallback-1"),
	})
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete diagnostics: %v", resp.Diagnostics)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one verification read and no move", requests)
	}
}

func TestAgentGroupAssignmentDeleteMissingAgentIsAlreadyGone(t *testing.T) {
	requests := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		requests++
		if req.URL.Path != "/v1/agent/find" {
			t.Fatalf("unexpected path: %s", req.URL.Path)
		}
		_, _ = w.Write([]byte(`{"error":"Success","response":{"agents":[]}}`))
	}))
	defer server.Close()
	apiClient, err := client.New(client.Config{URL: server.URL, APIKey: "test-key"})
	if err != nil {
		t.Fatal(err)
	}
	r := &agentGroupAssignmentResource{configuredResource: configuredResource{client: apiClient}}
	state := agentAssignmentTestState(t, r, agentGroupAssignmentModel{
		ID: types.StringValue("agent-1"), AgentID: types.StringValue("agent-1"),
		GroupID: types.StringValue("group-1"), DestroyFallbackGroupID: types.StringValue("fallback-1"),
	})
	resp := &resource.DeleteResponse{State: state}
	r.Delete(context.Background(), resource.DeleteRequest{State: state}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("delete diagnostics: %v", resp.Diagnostics)
	}
	if requests != 1 {
		t.Fatalf("requests = %d, want one read and no move", requests)
	}
}

func agentAssignmentTestState(t *testing.T, r *agentGroupAssignmentResource, model agentGroupAssignmentModel) tfsdk.State {
	t.Helper()
	var schemaResp resource.SchemaResponse
	r.Schema(context.Background(), resource.SchemaRequest{}, &schemaResp)
	state := tfsdk.State{Schema: schemaResp.Schema}
	if diags := state.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("set state: %v", diags)
	}
	return state
}
