export default defineNuxtRouteMiddleware(() => {
  const { isAuthed, isAdmin, hasAnyPermission } = useAuth()
  if (!isAuthed.value) {
    return navigateTo("/signin")
  }
  const adminCapable = isAdmin.value || hasAnyPermission([
    "users.read", "roles.read", "services.read", "tokens.read",
  ])
  if (!adminCapable) {
    throw createError({
      statusCode: 401,
      statusMessage: "Unauthorized",
      fatal: true,
    })
  }
})
