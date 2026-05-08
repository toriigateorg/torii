export default defineNuxtRouteMiddleware(() => {
  const { isAuthed } = useAuth()
  if (isAuthed.value) {
    return navigateTo("/dashboard")
  }
})
