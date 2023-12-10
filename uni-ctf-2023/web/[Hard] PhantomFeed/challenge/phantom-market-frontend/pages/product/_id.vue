<template>
    <div>
        <div v-if="isLoading" class="loading-container">
            <img class="loading-img" src="/icon.png">
        </div>
        <div v-else>
            <div v-if="isAuthenticated">
                <NavBar :phantom-feed-url="authServer" :user-data="userData"/>
                <div class="container mt-5 pt-5 mb-5">
                    <div class="row product-listing">
                        <h1>{{ product.title }}</h1>
                        <hr>
                        <div class="row">
                            <div class="col-4">
                                <img class="mb-3 w-100 w-75" :src="'/backend/static/' + product.image_link">
                            </div>
                            <div class="col-6">
                                <p class="h4">{{ product.description }}</p>
                                <br>
                                <span class="price-listing">{{ product.price }}</span>
                                <br>
                                <br>
                                <button @click="orderProduct()" class="button-listing">place order</button>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
  
<script>
import NavBar from "../../components/NavBar.vue";

export default {
    name: "ProductPage",
    data() {
        return {
            isAuthenticated: false,
            isLoading: true,
            product: null,
            userData: null
        };
    },
    async mounted() {
        this.authServer = this.$globalValues.authServer;
        this.marketServer = this.$globalValues.marketServer;
        this.clientId = this.$globalValues.clientId;

        this.isAuthenticated = await this.checkAuth();
        if (this.isAuthenticated) {
            this.product = JSON.parse(JSON.stringify(await this.fetchProduct())).message;
        } else {
            this.$router.push("/");
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
        async fetchProduct() {
            const token = this.getCookie("access_token");
            this.$axios.setHeader("Authorization", `Bearer ${token}`);
            return await this.$axios.$get(this.$globalValues.resourceServer + "/products/" + this.$route.params.id);
        },
        async orderProduct() {
            const token = this.getCookie("access_token");
            this.$axios.setHeader("Authorization", `Bearer ${token}`);
            await this.$axios.$post(this.$globalValues.resourceServer + "/order/" + this.$route.params.id);
            alert("Order placed");
        },
        parseJwt(token) {
            if (!token) { return; }
            const base64Url = token.split(".")[1];
            const base64 = base64Url.replace("-", "+").replace("_", "/");
            return JSON.parse(window.atob(base64));
        }
    },
    components: { NavBar }
}
</script>
  