<template>
  <div>
    <div v-if="isLoading" class="loading-container">
      <img class="loading-img" src="/icon.png">
    </div>
    <div v-else>
      <div v-if="isAuthenticated">
        <NavBar :user-data="userData" :phantom-feed-url="authServer"/>
        <div v-if="products" :products="products">
          <div class="container product-container mt-5 pt-5 mb-5">
            <div class="product" v-for="(product, index) in products" :key="index">
              <ProductCard :product="product" />
            </div>
          </div>
        </div>
      </div>
      <div v-else>
        <div class="container center col-4">
          <LoginCard :auth="authServer" :market="marketServer" :clientid="clientId" />
        </div>
      </div>
    </div>
  </div>
</template>

<script>
import LoginCard from "../components/LoginCard.vue";
import NavBar from "../components/NavBar.vue";
import ProductCard from "../components/ProductCard.vue";

export default {
  name: "IndexPage",
  data() {
    return {
      isAuthenticated: false,
      isLoading: true,
      products: null,
      authServer: null,
      marketServer: null,
      clientId: null,
      userData: null
    };
  },
  async mounted() {
    this.authServer = this.$globalValues.authServer;
    this.marketServer = this.$globalValues.marketServer;
    this.clientId = this.$globalValues.clientId;

    this.isAuthenticated = await this.checkAuth();

    if (this.isAuthenticated) {
      this.products = JSON.parse(JSON.stringify(await this.fetchProducts())).message;
    }

    this.isLoading = false;
  },
  methods: {
    getCookie(cookieName) {
      const cookies = document.cookie.split("; ");
      for (let i = 0; i < cookies.length; i++) {
        const cookie = cookies[i].split("=");
        const name = cookie[0];
        const value = cookie[1];
        if (name === cookieName) {
          return decodeURIComponent(value);
        }
      }
      return null;
    },
    async checkAuth() {
      const token = this.getCookie("access_token");
      if (!token) {
        return false;
      }
      try {
        this.$axios.setHeader("Authorization", `Bearer ${token}`);
        await this.$axios.$get(this.$globalValues.resourceServer);
        this.userData = this.parseJwt(token);
        return true;
      }
      catch {
        return false;
      }
    },
    async fetchProducts() {
      const token = this.getCookie("access_token");
      this.$axios.setHeader("Authorization", `Bearer ${token}`);
      return await this.$axios.$get(this.$globalValues.resourceServer + "/products/all");
    },
    parseJwt(token) {
      if (!token) { return; }
      const base64Url = token.split(".")[1];
      const base64 = base64Url.replace("-", "+").replace("_", "/");
      return JSON.parse(window.atob(base64));
    }
  },
  components: { LoginCard, ProductCard, NavBar }
}
</script>