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
	ID      types.String `tfsdk:"id"`
	AgentID types.String `tfsdk:"agent_id"`
	GroupID types.String `tfsdk:"group_id"`
}

func NewAgentGroupAssignmentResource() resource.Resource { return &agentGroupAssignmentResource{} }

func (r *agentGroupAssignmentResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_agent_group_assignment"
}

func (r *agentGroupAssignmentResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{Description: "Assign an Airlock endpoint agent to a policy group. Destroying this resource removes Terraform state only; Airlock does not expose a safe unassigned endpoint state, so use a replacement assignment to move the agent elsewhere.", Attributes: map[string]schema.Attribute{
		"id":       schema.StringAttribute{Computed: true, Description: "Airlock agent ID."},
		"agent_id": schema.StringAttribute{Required: true, Description: "Airlock endpoint agent ID from the airlock_agents data source or /v1/agent/find.", PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()}},
		"group_id": schema.StringAttribute{Required: true, Description: "Destination Airlock policy group ID."},
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

func (r *agentGroupAssignmentResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	resp.State.RemoveResource(ctx)
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
