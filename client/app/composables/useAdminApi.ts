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

export function useAdminApi() {
  const { authHeaders } = useAuth()

  const opts = () => ({
    headers: authHeaders(),
    credentials: "include" as const,
  })

  return {
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
  }
}
