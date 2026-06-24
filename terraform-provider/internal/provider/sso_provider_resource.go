package provider

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type ssoProviderResource struct {
	c *client.Client
}

func NewSSOProviderResource() resource.Resource { return &ssoProviderResource{} }

type ssoProviderModel struct {
	ID           types.String `tfsdk:"id"`
	Slug         types.String `tfsdk:"slug"`
	Name         types.String `tfsdk:"name"`
	IssuerURL    types.String `tfsdk:"issuer_url"`
	ClientID     types.String `tfsdk:"client_id"`
	ClientSecret types.String `tfsdk:"client_secret"`
	HasSecret    types.Bool   `tfsdk:"has_secret"`
	Scopes       types.String `tfsdk:"scopes"`
	Enabled      types.Bool   `tfsdk:"enabled"`
	AllowSignup  types.Bool   `tfsdk:"allow_signup"`
	LinkByEmail  types.Bool   `tfsdk:"link_by_email"`
	CreatedAt    types.String `tfsdk:"created_at"`
	UpdatedAt    types.String `tfsdk:"updated_at"`
}

func (r *ssoProviderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_sso_provider"
}

func (r *ssoProviderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "An OIDC single sign-on provider.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"slug": schema.StringAttribute{
				Required:    true,
				Description: "Lowercase URL-safe identifier (e.g. \"google\").",
			},
			"name":       schema.StringAttribute{Required: true},
			"issuer_url": schema.StringAttribute{Required: true},
			"client_id":  schema.StringAttribute{Required: true},
			"client_secret": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "OIDC client secret. Write-only: the API never returns it, so drift cannot be detected. Use has_secret to check whether one is set.",
			},
			"has_secret": schema.BoolAttribute{
				Computed:    true,
				Description: "Whether a client secret is stored server-side.",
			},
			"scopes": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Space-separated OIDC scopes. Must include \"openid\". Defaults to \"openid email profile\".",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"enabled": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Whether the provider is offered for sign-in. Defaults to true.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"allow_signup": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Allow unknown users to sign up via this provider. Defaults to false.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"link_by_email": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Link to an existing local user matching the email claim. Defaults to true.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

func (r *ssoProviderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *ssoProviderModel) toWrite() client.SSOWrite {
	w := client.SSOWrite{
		Slug:      m.Slug.ValueString(),
		Name:      m.Name.ValueString(),
		IssuerURL: m.IssuerURL.ValueString(),
		ClientID:  m.ClientID.ValueString(),
		Scopes:    m.Scopes.ValueString(),
	}
	if !m.ClientSecret.IsNull() && !m.ClientSecret.IsUnknown() {
		v := m.ClientSecret.ValueString()
		w.ClientSecret = &v
	}
	if !m.Enabled.IsNull() && !m.Enabled.IsUnknown() {
		v := m.Enabled.ValueBool()
		w.Enabled = &v
	}
	if !m.AllowSignup.IsNull() && !m.AllowSignup.IsUnknown() {
		v := m.AllowSignup.ValueBool()
		w.AllowSignup = &v
	}
	if !m.LinkByEmail.IsNull() && !m.LinkByEmail.IsUnknown() {
		v := m.LinkByEmail.ValueBool()
		w.LinkByEmail = &v
	}
	return w
}

// setSSOState copies the server response into the model. client_secret is
// never returned, so the caller is responsible for preserving the plan value.
func setSSOState(m *ssoProviderModel, p *client.SSOProvider) {
	m.ID = types.StringValue(p.ID)
	m.Slug = types.StringValue(p.Slug)
	m.Name = types.StringValue(p.Name)
	m.IssuerURL = types.StringValue(p.IssuerURL)
	m.ClientID = types.StringValue(p.ClientID)
	m.HasSecret = types.BoolValue(p.HasSecret)
	m.Scopes = types.StringValue(p.Scopes)
	m.Enabled = types.BoolValue(p.Enabled)
	m.AllowSignup = types.BoolValue(p.AllowSignup)
	m.LinkByEmail = types.BoolValue(p.LinkByEmail)
	m.CreatedAt = types.StringValue(p.CreatedAt)
	m.UpdatedAt = types.StringValue(p.UpdatedAt)
}

func (r *ssoProviderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan ssoProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.CreateSSO(ctx, plan.toWrite())
	if err != nil {
		resp.Diagnostics.AddError("create sso provider failed", err.Error())
		return
	}
	secret := plan.ClientSecret
	setSSOState(&plan, out)
	plan.ClientSecret = secret
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssoProviderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state ssoProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.GetSSO(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read sso provider failed", err.Error())
		return
	}
	secret := state.ClientSecret
	setSSOState(&state, out)
	state.ClientSecret = secret
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *ssoProviderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state ssoProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.UpdateSSO(ctx, state.ID.ValueString(), plan.toWrite())
	if err != nil {
		resp.Diagnostics.AddError("update sso provider failed", err.Error())
		return
	}
	secret := plan.ClientSecret
	setSSOState(&plan, out)
	plan.ClientSecret = secret
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *ssoProviderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state ssoProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteSSO(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("delete sso provider failed", err.Error())
	}
}

func (r *ssoProviderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
