package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type serviceDataSource struct {
	c *client.Client
}

func NewServiceDataSource() datasource.DataSource { return &serviceDataSource{} }

type serviceDataModel struct {
	ID                types.String `tfsdk:"id"`
	Title             types.String `tfsdk:"title"`
	Description       types.String `tfsdk:"description"`
	ServiceURL        types.String `tfsdk:"service_url"`
	Domain            types.String `tfsdk:"domain"`
	Headers           types.Map    `tfsdk:"headers"`
	PreserveHost      types.Bool   `tfsdk:"preserve_host"`
	PassthroughErrors types.Bool   `tfsdk:"passthrough_errors"`
	MaxBodySize       types.Int64  `tfsdk:"max_body_size"`
	ReadTimeoutSecs   types.Int64  `tfsdk:"read_timeout_secs"`
	WriteTimeoutSecs  types.Int64  `tfsdk:"write_timeout_secs"`
	DialTimeoutSecs   types.Int64  `tfsdk:"dial_timeout_secs"`
	CreatedAt         types.String `tfsdk:"created_at"`
	UpdatedAt         types.String `tfsdk:"updated_at"`
}

func (d *serviceDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (d *serviceDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Look up an existing torii service by id or domain.",
		Attributes: map[string]schema.Attribute{
			"id":          schema.StringAttribute{Optional: true, Computed: true, Description: "Service id. Provide this or domain."},
			"domain":      schema.StringAttribute{Optional: true, Computed: true, Description: "Service domain. Provide this or id."},
			"title":       schema.StringAttribute{Computed: true},
			"description": schema.StringAttribute{Computed: true},
			"service_url": schema.StringAttribute{Computed: true},
			"headers": schema.MapAttribute{
				Computed:    true,
				ElementType: types.StringType,
			},
			"preserve_host":      schema.BoolAttribute{Computed: true},
			"passthrough_errors": schema.BoolAttribute{Computed: true},
			"max_body_size":      schema.Int64Attribute{Computed: true},
			"read_timeout_secs":  schema.Int64Attribute{Computed: true},
			"write_timeout_secs": schema.Int64Attribute{Computed: true},
			"dial_timeout_secs":  schema.Int64Attribute{Computed: true},
			"created_at":         schema.StringAttribute{Computed: true},
			"updated_at":         schema.StringAttribute{Computed: true},
		},
	}
}

func (d *serviceDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *serviceDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var cfg serviceDataModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	hasID := !cfg.ID.IsNull() && cfg.ID.ValueString() != ""
	hasDomain := !cfg.Domain.IsNull() && cfg.Domain.ValueString() != ""
	if hasID == hasDomain {
		resp.Diagnostics.AddError("invalid lookup", "exactly one of id or domain must be set")
		return
	}

	var (
		svc *client.Service
		err error
	)
	if hasID {
		svc, err = d.c.GetService(ctx, cfg.ID.ValueString())
	} else {
		svc, err = d.c.FindServiceByDomain(ctx, cfg.Domain.ValueString())
	}
	if err != nil {
		if client.IsNotFound(err) {
			resp.Diagnostics.AddError("service not found", "no service matched the given id or domain")
			return
		}
		resp.Diagnostics.AddError("read service failed", err.Error())
		return
	}

	out := serviceDataModel{
		ID:                types.StringValue(svc.ID),
		Title:             types.StringValue(svc.Title),
		Description:       types.StringValue(svc.Description),
		ServiceURL:        types.StringValue(svc.ServiceURL),
		Domain:            types.StringValue(svc.Domain),
		PreserveHost:      types.BoolValue(svc.PreserveHost),
		PassthroughErrors: types.BoolValue(svc.PassthroughErrors),
		MaxBodySize:       types.Int64Value(svc.MaxBodySize),
		ReadTimeoutSecs:   types.Int64Value(int64(svc.ReadTimeoutSecs)),
		WriteTimeoutSecs:  types.Int64Value(int64(svc.WriteTimeoutSecs)),
		DialTimeoutSecs:   types.Int64Value(int64(svc.DialTimeoutSecs)),
		CreatedAt:         types.StringValue(svc.CreatedAt),
		UpdatedAt:         types.StringValue(svc.UpdatedAt),
	}
	headers := svc.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	hv, diag := types.MapValueFrom(ctx, types.StringType, headers)
	resp.Diagnostics.Append(diag...)
	if resp.Diagnostics.HasError() {
		return
	}
	out.Headers = hv
	resp.Diagnostics.Append(resp.State.Set(ctx, &out)...)
}
