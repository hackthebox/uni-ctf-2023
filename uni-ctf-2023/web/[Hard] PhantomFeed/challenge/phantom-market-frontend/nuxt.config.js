export default {
  // Global page headers: https://go.nuxtjs.dev/config-head
  head: {
    title: "Phantom Market",
    htmlAttrs: {
      lang: "en"
    },
    meta: [
      { charset: "utf-8" },
      { name: "viewport", content: "width=device-width, initial-scale=1" },
      { hid: "description", name: "description", content: "" },
      { name: "format-detection", content: "telephone=no" }
    ],
    link: [
      { rel: "icon", type: "image/png", href: "/icon.png" },
      { rel: "stylesheet", href: "https://fonts.googleapis.com/css2?family=Bruno+Ace&family=Nunito&display=swap"},
    ]
  },

  // Global CSS: https://go.nuxtjs.dev/config-css
  css: [
    "bootstrap/dist/css/bootstrap.css",
    "@/assets/phantommarket.css",
  ],

  server: {
    host: "0.0.0.0",
    port: 5000
  },

  // Plugins to run before rendering page: https://go.nuxtjs.dev/config-plugins
  plugins: [
    { src: "~/plugins/bootstrap.js", mode: "client" },
    { src: "~/plugins/global-values.js", ssr: false },
  ],

  // Auto import components: https://go.nuxtjs.dev/config-components
  components: true,

  // Modules for dev and build (recommended): https://go.nuxtjs.dev/config-modules
  buildModules: [
  ],

  modules: [
    "@nuxtjs/axios",
    "@nuxtjs/proxy",
  ],

  router: {
    base: "/"
  },
}
