package provider

import (
	"context"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type roleDataSource struct {
	c *client.Client
}

func NewRoleDataSource() datasource.DataSource { return &roleDataSource{} }

type roleDataModel struct {
	ID          types.String `tfsdk:"id"`
	Name        types.String `tfsdk:"name"`
	Description types.String `tfsdk:"description"`
	IsSystem    types.Bool   `tfsdk:"is_system"`
	Permissions types.Set    `tfsdk:"permissions"`
}

func (d *roleDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_role"
}

func (d *roleDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up an existing RBAC role by id or name.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Optional: true, Computed: true, Description: "Role id. Provide this or name."},
			"name":        schema.StringAttribute{Optional: true, Computed: true, Description: "Role name. Provide this or id."},
			"description": schema.StringAttribute{Computed: true},
			"is_system":   schema.BoolAttribute{Computed: true},
			"permissions": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
		},
	}
}

func (d *roleDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError("unexpected provider data", fmt.Sprintf("got %T", req.ProviderData))
		return
	}
	d.c = c
}

func (d *roleDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg roleDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasID := !cfg.ID.IsNull() && cfg.ID.ValueString() != ""
	hasName := !cfg.Name.IsNull() && cfg.Name.ValueString() != ""
	if hasID == hasName {
		resp.Diagnostics.AddError("invalid lookup", "exactly one of id or name must be set")
		return
	}

	var (
		role  *client.Role
		err   error
		perms []string
	)
	if hasID {
		role, err = d.c.GetRole(ctx, cfg.ID.ValueString())
		if err == nil {
			perms, err = d.c.GetRolePermissions(ctx, role.ID)
		}
	} else {
		role, err = d.c.FindRoleByName(ctx, cfg.Name.ValueString())
		if role != nil {
			perms = role.Permissions
		}
	}
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("role not found", "no role matched the given id or name")
			return
		}
		resp.Diagnostics.AddError("read role failed", err.Error())
		return
	}
	if perms == nil {
		perms = []string{}
	}
	sort.Strings(perms)
	pv, diag := types.SetValueFrom(ctx, types.StringType, perms)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}
	out := roleDataModel{
		ID:          types.StringValue(role.ID),
		Name:        types.StringValue(role.Name),
		Description: types.StringValue(role.Description),
		IsSystem:    types.BoolValue(role.IsSystem),
		Permissions: pv,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &out)...)
}
