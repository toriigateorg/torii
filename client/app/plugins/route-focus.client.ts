export default defineNuxtPlugin((nuxtApp) => {
  let isFirst = true

  nuxtApp.hook("page:finish", () => {
    if (isFirst) { isFirst = false; return }

    const main = document.getElementById("main-content")
    if (main) main.focus({ preventScroll: false })

    const announcer = document.getElementById("route-announcer")
    if (announcer) {
      const title = document.title || window.location.pathname
      announcer.textContent = ""
      setTimeout(() => { announcer.textContent = title }, 50)
    }
  })
})
