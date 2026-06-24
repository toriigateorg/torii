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

type permissionsDataSource struct {
	c *client.Client
}

func NewPermissionsDataSource() datasource.DataSource { return &permissionsDataSource{} }

type permissionsModel struct {
	Permissions types.Set `tfsdk:"permissions"`
}

func (d *permissionsDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_permissions"
}

func (d *permissionsDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The catalog of permission strings recognized by torii.",
		Attributes: map[string]schema.Attribute{
			"permissions": schema.SetAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "All valid permission strings (e.g. \"services.read\").",
			},
		},
	}
}

func (d *permissionsDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *permissionsDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	perms, err := d.c.ListAvailablePermissions(ctx)
	if err != nil {
		resp.Diagnostics.AddError("list permissions failed", err.Error())
		return
	}
	sort.Strings(perms)
	pv, diag := types.SetValueFrom(ctx, types.StringType, perms)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &permissionsModel{Permissions: pv})...)
}
