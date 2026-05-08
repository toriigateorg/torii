import type { AuthUser } from "./useAuth"

export interface PageMeta {
  page: number
  page_size: number
  total: number
}

export interface UserListResponse extends PageMeta {
  items: AuthUser[]
}

export interface CreateUserPayload {
  username: string
  email: string
  password: string
  first_name: string
  last_name: string
}

export type TokenStatus = "active" | "revoked" | "expired"

export interface TokenSession {
  id: string
  user_id: string
  username: string
  email: string
  created_at: string
  expires_at: string
  revoked_at: string | null
  status: TokenStatus
  is_current: boolean
}

export interface TokenListResponse extends PageMeta {
  items: TokenSession[]
}

export interface Service {
  id: string
  title: string
  description: string
  service_url: string
  domain: string
  headers: Record<string, string>
  created_at: string
  updated_at: string
}

export interface ServiceListResponse extends PageMeta {
  items: Service[]
}

export interface ServicePayload {
  title: string
  description: string
  service_url: string
  domain: string
  headers: Record<string, string>
}

export interface Role {
  id: string
  name: string
  description: string
  is_system: boolean
  permissions: string[]
  created_at: string
  updated_at: string
}

export interface RoleListResponse extends PageMeta {
  items: Role[]
}

export interface CreateRolePayload {
  name: string
  description: string
  permissions: string[]
}

export interface UpdateRolePayload {
  name?: string
  description?: string
}

export interface SSOProvider {
  id: string
  slug: string
  name: string
  issuer_url: string
  client_id: string
  has_secret: boolean
  scopes: string
  enabled: boolean
  allow_signup: boolean
  link_by_email: boolean
  created_at: string
  updated_at: string
}

export interface SSOProviderListResponse extends PageMeta {
  items: SSOProvider[]
}

export interface AppSettings {
  signup_enabled: boolean
}

export interface UpdateAppSettingsPayload {
  signup_enabled?: boolean
}

export interface AuditLog {
  id: string
  created_at: string
  event_type: string
  actor_user_id: string | null
  actor_username: string
  target_type: string
  target_id: string | null
  target_name: string
  client_ip: string
  user_agent: string
  metadata: Record<string, unknown>
}

export interface AuditLogListResponse extends PageMeta {
  items: AuditLog[]
}

export interface AuditLogQuery {
  page?: number
  page_size?: number
  actor_user_id?: string
  event_type?: string
  target_type?: string
  target_id?: string
  from?: string
  to?: string
}

export interface SSOProviderPayload {
  slug: string
  name: string
  issuer_url: string
  client_id: string
  client_secret?: string
  scopes: string
  enabled: boolean
  allow_signup: boolean
  link_by_email: boolean
}

export interface APIToken {
  id: string
  user_id: string
  username: string
  email: string
  name: string
  prefix: string
  created_at: string
  expires_at: string | null
  last_used_at: string | null
}

export interface APITokenListResponse extends PageMeta {
  items: APIToken[]
}

export interface CreateAPITokenPayload {
  user_id: string
  name: string
  expires_at?: string | null
}

export interface CreateAPITokenResponse extends APIToken {
  token: string
}

export type StatsWindow = "7d" | "30d" | "90d"

export interface StatsResponse {
  window: StatsWindow
  counters: {
    users: number
    admins: number
    services: number
    roles: number
    sso_providers: number
    active_sessions: number
  }
  activity: { day: string; count: number }[]
  top_services: { id: string; title: string; domain: string; access_count: number }[]
}

export function useAdminApi() {
  const { authHeaders } = useAuth()

  const opts = () => ({
    headers: authHeaders(),
    credentials: "include" as const,
  })

  return {
    stats(window: StatsWindow) {
      return $fetch<StatsResponse>("/api/v1/admin/stats", {
        ...opts(),
        query: { window },
      })
    },
    listUsers(page: number, pageSize = 20) {
      return $fetch<UserListResponse>("/api/v1/admin/users", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    createUser(payload: CreateUserPayload) {
      return $fetch<AuthUser>("/api/v1/admin/users", {
        ...opts(),
        method: "POST",
        body: payload,
      })
    },
    deleteUser(id: string) {
      return $fetch(`/api/v1/admin/users/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    listUserRoles(userId: string) {
      return $fetch<{ items: Role[] }>(`/api/v1/admin/users/${userId}/roles`, opts())
    },
    assignUserRole(userId: string, roleId: string) {
      return $fetch(`/api/v1/admin/users/${userId}/roles`, {
        ...opts(),
        method: "POST",
        body: { role_id: roleId },
      })
    },
    revokeUserRole(userId: string, roleId: string) {
      return $fetch(`/api/v1/admin/users/${userId}/roles/${roleId}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    listTokens(page: number, pageSize = 20) {
      return $fetch<TokenListResponse>("/api/v1/admin/tokens", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    revokeToken(id: string) {
      return $fetch(`/api/v1/admin/tokens/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    cleanupExpiredTokens() {
      return $fetch<{ deleted: number }>("/api/v1/admin/tokens/cleanup", {
        ...opts(),
        method: "POST",
      })
    },
    listServices(page: number, pageSize = 20) {
      return $fetch<ServiceListResponse>("/api/v1/admin/services", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    createService(payload: ServicePayload) {
      return $fetch<Service>("/api/v1/admin/services", {
        ...opts(),
        method: "POST",
        body: payload,
      })
    },
    updateService(id: string, payload: ServicePayload) {
      return $fetch<Service>(`/api/v1/admin/services/${id}`, {
        ...opts(),
        method: "PATCH",
        body: payload,
      })
    },
    deleteService(id: string) {
      return $fetch(`/api/v1/admin/services/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    listRoles(page: number, pageSize = 20) {
      return $fetch<RoleListResponse>("/api/v1/admin/roles", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    getRole(id: string) {
      return $fetch<Role>(`/api/v1/admin/roles/${id}`, opts())
    },
    createRole(payload: CreateRolePayload) {
      return $fetch<Role>("/api/v1/admin/roles", {
        ...opts(),
        method: "POST",
        body: payload,
      })
    },
    updateRole(id: string, payload: UpdateRolePayload) {
      return $fetch<Role>(`/api/v1/admin/roles/${id}`, {
        ...opts(),
        method: "PATCH",
        body: payload,
      })
    },
    deleteRole(id: string) {
      return $fetch(`/api/v1/admin/roles/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    setRolePermissions(id: string, permissions: string[]) {
      return $fetch<{ permissions: string[] }>(`/api/v1/admin/roles/${id}/permissions`, {
        ...opts(),
        method: "PUT",
        body: { permissions },
      })
    },
    listRoleServices(id: string) {
      return $fetch<{ items: Service[] }>(`/api/v1/admin/roles/${id}/services`, opts())
    },
    assignRoleService(roleId: string, serviceId: string) {
      return $fetch(`/api/v1/admin/roles/${roleId}/services`, {
        ...opts(),
        method: "POST",
        body: { service_id: serviceId },
      })
    },
    revokeRoleService(roleId: string, serviceId: string) {
      return $fetch(`/api/v1/admin/roles/${roleId}/services/${serviceId}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    listRoleUsers(id: string, page: number, pageSize = 20) {
      return $fetch<UserListResponse>(`/api/v1/admin/roles/${id}/users`, {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    listPermissions() {
      return $fetch<{ items: string[] }>("/api/v1/admin/permissions", opts())
    },
    listSSO(page: number, pageSize = 20) {
      return $fetch<SSOProviderListResponse>("/api/v1/admin/sso", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    createSSO(payload: SSOProviderPayload) {
      return $fetch<SSOProvider>("/api/v1/admin/sso", {
        ...opts(),
        method: "POST",
        body: payload,
      })
    },
    updateSSO(id: string, payload: SSOProviderPayload) {
      return $fetch<SSOProvider>(`/api/v1/admin/sso/${id}`, {
        ...opts(),
        method: "PATCH",
        body: payload,
      })
    },
    deleteSSO(id: string) {
      return $fetch(`/api/v1/admin/sso/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    getSettings() {
      return $fetch<AppSettings>("/api/v1/admin/settings", opts())
    },
    updateSettings(payload: UpdateAppSettingsPayload) {
      return $fetch<AppSettings>("/api/v1/admin/settings", {
        ...opts(),
        method: "PUT",
        body: payload,
      })
    },
    listAPITokens(page: number, pageSize = 20) {
      return $fetch<APITokenListResponse>("/api/v1/admin/api_tokens", {
        ...opts(),
        query: { page, page_size: pageSize },
      })
    },
    createAPIToken(payload: CreateAPITokenPayload) {
      return $fetch<CreateAPITokenResponse>("/api/v1/admin/api_tokens", {
        ...opts(),
        method: "POST",
        body: payload,
      })
    },
    deleteAPIToken(id: string) {
      return $fetch(`/api/v1/admin/api_tokens/${id}`, {
        ...opts(),
        method: "DELETE",
      })
    },
    listAuditLogs(query: AuditLogQuery = {}) {
      const q: Record<string, string | number> = {}
      if (query.page) q.page = query.page
      if (query.page_size) q.page_size = query.page_size
      if (query.actor_user_id) q.actor_user_id = query.actor_user_id
      if (query.event_type) q.event_type = query.event_type
      if (query.target_type) q.target_type = query.target_type
      if (query.target_id) q.target_id = query.target_id
      if (query.from) q.from = query.from
      if (query.to) q.to = query.to
      return $fetch<AuditLogListResponse>("/api/v1/admin/audit", {
        ...opts(),
        query: q,
      })
    },
  }
}
