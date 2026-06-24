package provider

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int64planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/toriigateorg/torii/terraform-provider/internal/client"
)

type serviceResource struct {
	c *client.Client
}

func NewServiceResource() resource.Resource { return &serviceResource{} }

type serviceModel struct {
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

func (r *serviceResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_service"
}

func (r *serviceResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "A service proxied by torii.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"title":       schema.StringAttribute{Required: true},
			"description": schema.StringAttribute{Optional: true, Computed: true},
			"service_url": schema.StringAttribute{Required: true},
			"domain": schema.StringAttribute{
				Required:    true,
				Description: "Hostname[:port] of the service. Lowercased server-side.",
			},
			"headers": schema.MapAttribute{
				Optional:    true,
				Computed:    true,
				ElementType: types.StringType,
				Description: "Headers to overlay onto proxied requests.",
			},
			"preserve_host": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Forward the client's Host header to the upstream instead of rewriting it. Defaults to false.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"passthrough_errors": schema.BoolAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Pass upstream 5xx responses through unchanged. Defaults to true.",
				PlanModifiers: []planmodifier.Bool{boolplanmodifier.UseStateForUnknown()},
			},
			"max_body_size": schema.Int64Attribute{
				Optional:      true,
				Computed:      true,
				Description:   "Maximum request body size in bytes. Defaults to 1048576 (1 MiB).",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"read_timeout_secs": schema.Int64Attribute{
				Optional:      true,
				Computed:      true,
				Description:   "Upstream read timeout in seconds (0 = no timeout). Defaults to 30.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"write_timeout_secs": schema.Int64Attribute{
				Optional:      true,
				Computed:      true,
				Description:   "Upstream write timeout in seconds (0 = no timeout). Defaults to 60.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"dial_timeout_secs": schema.Int64Attribute{
				Optional:      true,
				Computed:      true,
				Description:   "Upstream dial timeout in seconds (0 = no timeout). Defaults to 30.",
				PlanModifiers: []planmodifier.Int64{int64planmodifier.UseStateForUnknown()},
			},
			"created_at": schema.StringAttribute{Computed: true},
			"updated_at": schema.StringAttribute{Computed: true},
		},
	}
}

func (r *serviceResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

func (m *serviceModel) toWrite(ctx context.Context) (client.ServiceWrite, error) {
	headers := map[string]string{}
	if !m.Headers.IsNull() && !m.Headers.IsUnknown() {
		if diag := m.Headers.ElementsAs(ctx, &headers, false); diag.HasError() {
			return client.ServiceWrite{}, fmt.Errorf("headers: %s", diag.Errors())
		}
	}
	w := client.ServiceWrite{
		Title:        m.Title.ValueString(),
		Description:  m.Description.ValueString(),
		ServiceURL:   m.ServiceURL.ValueString(),
		Domain:       strings.ToLower(m.Domain.ValueString()),
		Headers:      headers,
		PreserveHost: m.PreserveHost.ValueBool(),
	}
	// Only send the optional fields when known so an unset attribute keeps the
	// server default instead of being forced to the type's zero value.
	if !m.PassthroughErrors.IsNull() && !m.PassthroughErrors.IsUnknown() {
		v := m.PassthroughErrors.ValueBool()
		w.PassthroughErrors = &v
	}
	if !m.MaxBodySize.IsNull() && !m.MaxBodySize.IsUnknown() {
		v := m.MaxBodySize.ValueInt64()
		w.MaxBodySize = &v
	}
	if !m.ReadTimeoutSecs.IsNull() && !m.ReadTimeoutSecs.IsUnknown() {
		v := int32(m.ReadTimeoutSecs.ValueInt64())
		w.ReadTimeoutSecs = &v
	}
	if !m.WriteTimeoutSecs.IsNull() && !m.WriteTimeoutSecs.IsUnknown() {
		v := int32(m.WriteTimeoutSecs.ValueInt64())
		w.WriteTimeoutSecs = &v
	}
	if !m.DialTimeoutSecs.IsNull() && !m.DialTimeoutSecs.IsUnknown() {
		v := int32(m.DialTimeoutSecs.ValueInt64())
		w.DialTimeoutSecs = &v
	}
	return w, nil
}

func setServiceState(ctx context.Context, m *serviceModel, s *client.Service) error {
	m.ID = types.StringValue(s.ID)
	m.Title = types.StringValue(s.Title)
	m.Description = types.StringValue(s.Description)
	m.ServiceURL = types.StringValue(s.ServiceURL)
	m.Domain = types.StringValue(s.Domain)
	headers := s.Headers
	if headers == nil {
		headers = map[string]string{}
	}
	hv, diag := types.MapValueFrom(ctx, types.StringType, headers)
	if diag.HasError() {
		return fmt.Errorf("headers: %s", diag.Errors())
	}
	m.Headers = hv
	m.PreserveHost = types.BoolValue(s.PreserveHost)
	m.PassthroughErrors = types.BoolValue(s.PassthroughErrors)
	m.MaxBodySize = types.Int64Value(s.MaxBodySize)
	m.ReadTimeoutSecs = types.Int64Value(int64(s.ReadTimeoutSecs))
	m.WriteTimeoutSecs = types.Int64Value(int64(s.WriteTimeoutSecs))
	m.DialTimeoutSecs = types.Int64Value(int64(s.DialTimeoutSecs))
	m.CreatedAt = types.StringValue(s.CreatedAt)
	m.UpdatedAt = types.StringValue(s.UpdatedAt)
	return nil
}

func (r *serviceResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in, err := plan.toWrite(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid plan", err.Error())
		return
	}
	out, err := r.c.CreateService(ctx, in)
	if err != nil {
		resp.Diagnostics.AddError("create service failed", err.Error())
		return
	}
	if err := setServiceState(ctx, &plan, out); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	out, err := r.c.GetService(ctx, state.ID.ValueString())
	if err != nil {
		if client.IsNotFound(err) {
			resp.State.RemoveResource(ctx)
			return
		}
		resp.Diagnostics.AddError("read service failed", err.Error())
		return
	}
	if err := setServiceState(ctx, &state, out); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *serviceResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state serviceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	in, err := plan.toWrite(ctx)
	if err != nil {
		resp.Diagnostics.AddError("invalid plan", err.Error())
		return
	}
	out, err := r.c.UpdateService(ctx, state.ID.ValueString(), in)
	if err != nil {
		resp.Diagnostics.AddError("update service failed", err.Error())
		return
	}
	plan.ID = state.ID
	if err := setServiceState(ctx, &plan, out); err != nil {
		resp.Diagnostics.AddError("decode response", err.Error())
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *serviceResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state serviceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}
	if err := r.c.DeleteService(ctx, state.ID.ValueString()); err != nil && !client.IsNotFound(err) {
		resp.Diagnostics.AddError("delete service failed", err.Error())
	}
}

func (r *serviceResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), req.ID)...)
}
