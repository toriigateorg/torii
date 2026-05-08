export default defineNuxtPlugin(async () => {
  const { bootstrap } = useAuth()
  await bootstrap()
})
