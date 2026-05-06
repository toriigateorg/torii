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
  }
}
