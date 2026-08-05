package provider

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

type agentGroupAssignmentResource struct{ configuredResource }

type agentGroupAssignmentModel struct {
	ID                     types.String `tfsdk:"id"`
	AgentID                types.String `tfsdk:"agent_id"`
	GroupID                types.String `tfsdk:"group_id"`
	DestroyFallbackGroupID types.String `tfsdk:"destroy_fallback_group_id"`
}

func NewAgentGroupAssignmentResource() resource.Resource { return &agentGroupAssignmentResource{} }

func (r *agentGroupAssignmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_group_assignment"
}

func (r *agentGroupAssignmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Assign an Airlock endpoint agent to a policy group. Destroy fails closed unless an explicit fallback group is configured.", Attributes: map[string]schema.Attribute{
		"id":                        schema.StringAttribute{Computed: true, Description: "Airlock agent ID."},
		"agent_id":                  schema.StringAttribute{Required: true, Description: "Airlock endpoint agent ID from the airlock_agents data source or /v1/agent/find.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"group_id":                  schema.StringAttribute{Required: true, Description: "Destination Airlock policy group ID."},
		"destroy_fallback_group_id": schema.StringAttribute{Optional: true, Description: "Policy group to move the agent to before destroying this resource. Destroy fails when this is not configured."},
	}}
}

func (r *agentGroupAssignmentResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan agentGroupAssignmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.client.MoveAgent(ctx, plan.AgentID.ValueString(), plan.GroupID.ValueString()); err != nil {
		resp.Diagnostics.AddError("Unable to move Airlock agent", err.Error())
		return
	}
	plan.ID = plan.AgentID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentGroupAssignmentResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state agentGroupAssignmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	agent, ok, err := r.client.GetAgent(ctx, state.AgentID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock agent", err.Error())
		return
	}
	if !ok {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = state.AgentID
	state.GroupID = types.StringValue(agent.GroupID)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *agentGroupAssignmentResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan agentGroupAssignmentModel
	var prior agentGroupAssignmentModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &prior)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if !plan.GroupID.Equal(prior.GroupID) {
		if err := r.client.MoveAgent(ctx, plan.AgentID.ValueString(), plan.GroupID.ValueString()); err != nil {
			resp.Diagnostics.AddError("Unable to move Airlock agent", err.Error())
			return
		}
	}
	plan.ID = plan.AgentID
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *agentGroupAssignmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state agentGroupAssignmentModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.DestroyFallbackGroupID.IsNull() || state.DestroyFallbackGroupID.IsUnknown() || state.DestroyFallbackGroupID.ValueString() == "" {
		resp.Diagnostics.AddAttributeError(pathRoot("destroy_fallback_group_id"), "Missing destroy fallback group", "Configure destroy_fallback_group_id before destroying an Airlock agent group assignment.")
		return
	}
	fallbackID := state.DestroyFallbackGroupID.ValueString()
	agent, ok, err := r.client.GetAgent(ctx, state.AgentID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to read Airlock agent before destroy fallback", err.Error())
		return
	}
	if !ok {
		return
	}
	if agent.GroupID == fallbackID {
		return
	}
	if err := r.client.MoveAgent(ctx, state.AgentID.ValueString(), fallbackID); err != nil {
		resp.Diagnostics.AddError("Unable to move Airlock agent to destroy fallback group", err.Error())
		return
	}
	agent, ok, err = r.client.GetAgent(ctx, state.AgentID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Unable to verify Airlock agent destroy fallback", err.Error())
		return
	}
	if !ok || agent.GroupID != fallbackID {
		resp.Diagnostics.AddError("Unable to verify Airlock agent destroy fallback", "Airlock did not report the agent in the configured fallback group after the move.")
	}
}

func (r *agentGroupAssignmentResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	agent, ok, err := r.client.GetAgent(ctx, req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Unable to import Airlock agent group assignment", err.Error())
		return
	}
	if !ok {
		resp.Diagnostics.AddError("Unable to import Airlock agent group assignment", "No Airlock agent was found for the given agent ID.")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("agent_id"), req.ID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, pathRoot("group_id"), agent.GroupID)...)
}
