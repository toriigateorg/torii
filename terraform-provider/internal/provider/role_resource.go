package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type roleResource struct {
	c *client.Client
}

func NewRoleResource() resource.Resource { return &roleResource{} }

type roleModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IsSystem    types.Bool   `tfsdk:"is_system"`
	Permissions types.Set    `tfsdk:"permissions"`
}

func (r *roleResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (r *roleResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An RBAC role. Permissions are managed inline via PUT /admin/roles/:id/permissions.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name":        schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true},
			"is_system":   schema.BoolAttribute{Computed: true},
			"permissions": schema.SetAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Set of permission strings (e.g. \"services.read\"). Replaces the role's permissions on every change.",
			},
		},
	}
}

func (r *roleResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *roleModel) wantedPermissions(ctx context.Context) ([]string, error) {
	if m.Permissions.IsNull() || m.Permissions.IsUnknown() {
		return []string{}, nil
	}
	var perms []string
	if diag := m.Permissions.ElementsAs(ctx, &perms, false); diag.HasError() {
		return nil, fmt.Errorf("permissions: %s", diag.Errors())
	}
	sort.Strings(perms)
	return perms, nil
}

func setRoleState(ctx context.Context, m *roleModel, role *client.Role, perms []string) error {
	m.ID = types.StringValue(role.ID)
	m.Name = types.StringValue(role.Name)
	m.Description = types.StringValue(role.Description)
	m.IsSystem = types.BoolValue(role.IsSystem)
	if perms == nil {
		perms = []string{}
	}
	pv, diag := types.SetValueFrom(ctx, types.StringType, perms)
	if diag.HasError() {
		return fmt.Errorf("permissions: %s", diag.Errors())
	}
	m.Permissions = pv
	return nil
}

func (r *roleResource) refusesSystem(role *client.Role) (string, bool) {
	if role.IsSystem {
		return fmt.Sprintf("role %q is a built-in system role and cannot be managed by Terraform", role.Name), true
	}
	return "", false
}

func (r *roleResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	perms, err := plan.wantedPermissions(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid plan", err.Error())
		return
	}
	role, err := r.c.CreateRole(ctx, client.RoleCreate{
		Name:        plan.Name.ValueString(),
		Description: plan.Description.ValueString(),
		Permissions: perms,
	})
	if err != nil {
		resp.Diagnostics.AddError("create role failed", err.Error())
		return
	}
	if msg, sys := r.refusesSystem(role); sys {
		// Roll back so we don't leave torii in an inconsistent state.
		_ = r.c.DeleteRole(ctx, role.ID)
		resp.Diagnostics.AddError("system role", msg)
		return
	}
	gotPerms, err := r.c.GetRolePermissions(ctx, role.ID)
	if err != nil {
		resp.Diagnostics.AddError("read role permissions failed", err.Error())
		return
	}
	if err := setRoleState(ctx, &plan, role, gotPerms); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	role, err := r.c.GetRole(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read role failed", err.Error())
		return
	}
	perms, err := r.c.GetRolePermissions(ctx, role.ID)
	if err != nil {
		resp.Diagnostics.AddError("read role permissions failed", err.Error())
		return
	}
	if err := setRoleState(ctx, &state, role, perms); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *roleResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state roleModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.IsSystem.ValueBool() {
		resp.Diagnostics.AddError("system role", fmt.Sprintf("role %q is a built-in system role and cannot be managed by Terraform", state.Name.ValueString()))
		return
	}
	id := state.ID.ValueString()
	name := plan.Name.ValueString()
	desc := plan.Description.ValueString()
	role, err := r.c.UpdateRole(ctx, id, client.RoleUpdate{Name: &name, Description: &desc})
	if err != nil {
		resp.Diagnostics.AddError("update role failed", err.Error())
		return
	}
	wanted, err := plan.wantedPermissions(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid plan", err.Error())
		return
	}
	gotPerms, err := r.c.SetRolePermissions(ctx, id, wanted)
	if err != nil {
		resp.Diagnostics.AddError("set role permissions failed", err.Error())
		return
	}
	if err := setRoleState(ctx, &plan, role, gotPerms); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *roleResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state roleModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if state.IsSystem.ValueBool() {
		resp.Diagnostics.AddError("system role", fmt.Sprintf("refusing to delete built-in role %q", state.Name.ValueString()))
		return
	}
	if err := r.c.DeleteRole(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("delete role failed", err.Error())
	}
}

func (r *roleResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
