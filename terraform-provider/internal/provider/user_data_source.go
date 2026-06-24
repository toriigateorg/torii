package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type userDataSource struct {
	c *client.Client
}

func NewUserDataSource() datasource.DataSource { return &userDataSource{} }

type userDataModel struct {
	ID          types.String `tfsdk:"id"`
	Username    types.String `tfsdk:"username"`
	Email       types.String `tfsdk:"email"`
	FirstName   types.String `tfsdk:"first_name"`
	LastName    types.String `tfsdk:"last_name"`
	Permissions types.Set    `tfsdk:"permissions"`
}

func (d *userDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_user"
}

func (d *userDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up an existing torii user by id or username.",
		Attributes: map[string]schema.Attribute{
			"id":         schema.StringAttribute{Optional: true, Computed: true, Description: "User id. Provide this or username."},
			"username":   schema.StringAttribute{Optional: true, Computed: true, Description: "Username. Provide this or id."},
			"email":      schema.StringAttribute{Computed: true},
			"first_name": schema.StringAttribute{Computed: true},
			"last_name":  schema.StringAttribute{Computed: true},
			"permissions": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "Effective permissions the user has via their roles.",
			},
		},
	}
}

func (d *userDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *userDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg userDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasID := !cfg.ID.IsNull() && cfg.ID.ValueString() != ""
	hasUsername := !cfg.Username.IsNull() && cfg.Username.ValueString() != ""
	if hasID == hasUsername {
		resp.Diagnostics.AddError("invalid lookup", "exactly one of id or username must be set")
		return
	}

	var (
		user *client.User
		err  error
	)
	if hasID {
		user, err = d.c.GetUser(ctx, cfg.ID.ValueString())
	} else {
		user, err = d.c.FindUserByUsername(ctx, cfg.Username.ValueString())
	}
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("user not found", "no user matched the given id or username")
			return
		}
		resp.Diagnostics.AddError("read user failed", err.Error())
		return
	}

	perms := user.Permissions
	if perms == nil {
		perms = []string{}
	}
	pv, diag := types.SetValueFrom(ctx, types.StringType, perms)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}
	out := userDataModel{
		ID:          types.StringValue(user.ID),
		Username:    types.StringValue(user.Username),
		Email:       types.StringValue(user.Email),
		FirstName:   types.StringValue(user.FirstName),
		LastName:    types.StringValue(user.LastName),
		Permissions: pv,
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &out)...)
}
