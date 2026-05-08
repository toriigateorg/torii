package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type roleServiceResource struct {
	c *client.Client
}

func NewRoleServiceResource() resource.Resource { return &roleServiceResource{} }

type roleServiceModel struct {
	ID        types.String `tfsdk:"id"`
	RoleID    types.String `tfsdk:"role_id"`
	ServiceID types.String `tfsdk:"service_id"`
}

func (r *roleServiceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role_service"
}

func (r *roleServiceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	replace := []planmodifier.String{stringplanmodifier.RequiresReplace()}
	resp.Schema = schema.Schema{
		Description: "Grants a role access to a service. The composite ID is `<role_id>:<service_id>`.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"role_id":    schema.StringAttribute{Required: true, PlanModifiers: replace},
			"service_id": schema.StringAttribute{Required: true, PlanModifiers: replace},
		},
	}
}

func (r *roleServiceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	r.c = c
}

func compositeID(roleID, serviceID string) string { return roleID + ":" + serviceID }

func (r *roleServiceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleServiceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.AssignRoleService(ctx, plan.RoleID.ValueString(), plan.ServiceID.ValueString()); err != nil {
		resp.Diagnostics.AddError("assign role service failed", err.Error())
		return
	}
	plan.ID = types.StringValue(compositeID(plan.RoleID.ValueString(), plan.ServiceID.ValueString()))
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleServiceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	roleID := state.RoleID.ValueString()
	serviceID := state.ServiceID.ValueString()
	services, err := r.c.ListRoleServices(ctx, roleID)
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("list role services failed", err.Error())
		return
	}
	found := false
	for _, s := range services {
		if s.ID == serviceID {
			found = true
			break
		}
	}
	if !found {
		resp.State.RemoveResource(ctx)
		return
	}
	state.ID = types.StringValue(compositeID(roleID, serviceID))
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roleServiceResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("update not supported", "torii_role_service has no mutable attributes; both fields force replacement")
}

func (r *roleServiceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleServiceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.RevokeRoleService(ctx, state.RoleID.ValueString(), state.ServiceID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("revoke role service failed", err.Error())
	}
}

func (r *roleServiceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.SplitN(req.ID, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		resp.Diagnostics.AddError("invalid import id", "expected format <role_id>:<service_id>")
		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("role_id"), parts[0])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("service_id"), parts[1])...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
