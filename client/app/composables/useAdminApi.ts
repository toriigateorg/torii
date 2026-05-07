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
  user_type: "admin" | "user"
}

export type TokenStatus = "active" | "revoked" | "expired"

export interface TokenSession {
  id: string
  user_id: string
  username: string
  email: string
  user_type: string
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
  }
}
