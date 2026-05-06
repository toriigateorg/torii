export default defineNuxtRouteMiddleware(() => {
  const { isAuthed, user } = useAuth()
  if (!isAuthed.value) {
    return navigateTo("/signin")
  }
  if (user.value?.user_type !== "admin") {
    throw createError({
      statusCode: 401,
      statusMessage: "Unauthorized",
      fatal: true,
    })
  }
})
