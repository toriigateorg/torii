package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type toriiProvider struct {
	version string
}

type providerModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIToken types.String `tfsdk:"api_token"`
}

func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &toriiProvider{version: version}
	}
}

func (p *toriiProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "torii"
	resp.Version = p.version
}

func (p *toriiProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Manage torii services and RBAC roles via its admin API.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Description: "Base URL of the torii server, e.g. https://torii.example.com. May also be set via TORII_ENDPOINT.",
				Optional:    true,
			},
			"api_token": schema.StringAttribute{
				Description: "Long-lived API token (torii_pat_...). May also be set via TORII_API_TOKEN.",
				Optional:    true,
				Sensitive:   true,
			},
		},
	}
}

func (p *toriiProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var cfg providerModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := os.Getenv("TORII_ENDPOINT")
	if !cfg.Endpoint.IsNull() && !cfg.Endpoint.IsUnknown() {
		endpoint = cfg.Endpoint.ValueString()
	}
	apiToken := os.Getenv("TORII_API_TOKEN")
	if !cfg.APIToken.IsNull() && !cfg.APIToken.IsUnknown() {
		apiToken = cfg.APIToken.ValueString()
	}

	if endpoint == "" {
		resp.Diagnostics.AddError("endpoint required", "either set provider endpoint or TORII_ENDPOINT")
		return
	}
	if apiToken == "" {
		resp.Diagnostics.AddError("api_token required", "either set provider api_token or TORII_API_TOKEN")
		return
	}

	c, err := client.New(endpoint, apiToken, client.WithUserAgent("terraform-provider-torii/"+p.version))
	if err != nil {
		resp.Diagnostics.AddError("invalid provider configuration", err.Error())
		return
	}
	resp.ResourceData = c
	resp.DataSourceData = c
}

func (p *toriiProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewServiceResource,
		NewRoleResource,
		NewRoleServiceResource,
		NewUserResource,
		NewUserRoleResource,
		NewSSOProviderResource,
	}
}

func (p *toriiProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewPermissionsDataSource,
		NewServiceDataSource,
		NewRoleDataSource,
		NewUserDataSource,
	}
}
