export interface RoleSummary {
  id: string
  name: string
}

export interface AuthUser {
  id: string
  username: string
  email: string
  first_name: string
  last_name: string
  roles: RoleSummary[]
  permissions: string[]
}

interface TokenResponse {
  access_token: string
  expires_in: number
  user?: AuthUser
}

let refreshTimer: ReturnType<typeof setTimeout> | null = null

function clearRefreshTimer() {
  if (refreshTimer) {
    clearTimeout(refreshTimer)
    refreshTimer = null
  }
}

export function useAuth() {
  const accessToken = useState<string | null>("auth:access_token", () => null)
  const user = useState<AuthUser | null>("auth:user", () => null)
  const ready = useState<boolean>("auth:ready", () => false)

  const isAuthed = computed(() => !!accessToken.value && !!user.value)
  const isAdmin = computed(() => !!user.value?.roles?.some((r) => r.name === "admin"))

  function hasPermission(perm: string): boolean {
    return !!user.value?.permissions?.includes(perm)
  }

  function hasAnyPermission(perms: string[]): boolean {
    return perms.some((p) => hasPermission(p))
  }

  function scheduleRefresh(expiresIn: number) {
    clearRefreshTimer()
    // Refresh 15s before expiry, but never sooner than 5s and never later
    // than half the TTL — keeps silent refreshes cheap on long-TTL prod
    // configs while still working on the 60s short-TTL default.
    const lead = expiresIn <= 60 ? 15 : 30
    const ms = Math.max(5_000, Math.min((expiresIn / 2) * 1000, (expiresIn - lead) * 1000))
    refreshTimer = setTimeout(() => {
      void refresh().catch(() => {})
    }, ms)
  }

  function apply(data: TokenResponse) {
    accessToken.value = data.access_token
    if (data.user) user.value = data.user
    scheduleRefresh(data.expires_in)
  }

  function authHeaders(): Record<string, string> {
    return accessToken.value ? { Authorization: `Bearer ${accessToken.value}` } : {}
  }

  async function signup(payload: {
    username: string
    email: string
    password: string
    first_name?: string
    last_name?: string
  }) {
    const data = await $fetch<TokenResponse>("/api/v1/signup", {
      method: "POST",
      body: payload,
      credentials: "include",
    })
    apply(data)
  }

  async function signin(identifier: string, password: string) {
    const data = await $fetch<TokenResponse>("/api/v1/signin", {
      method: "POST",
      body: { identifier, password },
      credentials: "include",
    })
    apply(data)
  }

  async function refresh() {
    try {
      const data = await $fetch<TokenResponse>("/api/v1/token_refresh", {
        method: "POST",
        credentials: "include",
      })
      apply(data)
      if (!user.value) await fetchMe()
    } catch (err) {
      accessToken.value = null
      user.value = null
      clearRefreshTimer()
      throw err
    }
  }

  async function fetchMe() {
    if (!accessToken.value) return
    try {
      user.value = await $fetch<AuthUser>("/api/v1/me", {
        headers: authHeaders(),
        credentials: "include",
      })
    } catch {
      user.value = null
    }
  }

  async function signout() {
    try {
      await $fetch("/api/v1/logout", {
        method: "POST",
        credentials: "include",
      })
    } catch {}
    accessToken.value = null
    user.value = null
    clearRefreshTimer()
  }

  async function bootstrap() {
    if (ready.value) return
    try {
      await refresh()
    } catch {}
    ready.value = true
  }

  return {
    accessToken,
    user,
    ready,
    isAuthed,
    isAdmin,
    hasPermission,
    hasAnyPermission,
    signup,
    signin,
    refresh,
    signout,
    fetchMe,
    bootstrap,
    authHeaders,
  }
}
