<template>
    <div>
        <div v-if="isLoading" class="loading-container">
            <img class="loading-img" src="/icon.png">
        </div>
        <div v-else>
            <div v-if="isAuthenticated">
                <NavBar :phantom-feed-url="authServer" :user-data="userData" />
                <div class="container mt-5 pt-5 mb-5">
                    <div class="row product-listing">
                        <div class="col">
                            <h1>Orders</h1>
                        </div>
                        <div class="col-2">
                            <button class="button-listing float-right w-100" @click="exportPDF()">Export PDF</button>
                        </div>
                        <div class="row">
                            <hr>
                            <table>
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>Product ID</th>
                                        <th>User ID</th>
                                    </tr>
                                </thead>
                                <tbody>
                                    <tr v-for="(order, index) in orders" :key="index">
                                        <td>{{ order.id }}</td>
                                        <td>{{ order.product_id }}</td>
                                        <td>{{ order.user_id }}</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>
            </div>
        </div>
    </div>
</template>
  
<script>
import NavBar from "../components/NavBar.vue";

export default {
    name: "OrdersPage",
    data() {
        return {
            isAuthenticated: false,
            isLoading: true,
            orders: null,
            userData: null
        };
    },
    async mounted() {
        this.authServer = this.$globalValues.authServer;
        this.marketServer = this.$globalValues.marketServer;
        this.clientId = this.$globalValues.clientId;

        this.isAuthenticated = await this.checkAuth();
        if (this.isAuthenticated) {
            this.orders = JSON.parse(JSON.stringify(await this.fetchOrders())).message;
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
        async fetchOrders() {
            const token = this.getCookie("access_token");
            this.$axios.setHeader("Authorization", `Bearer ${token}`);
            return await this.$axios.$get(this.$globalValues.resourceServer + "/orders");
        },
        async exportPDF() {
            const token = this.getCookie("access_token");
            this.$axios.setHeader("Authorization", `Bearer ${token}`);

            const formData = new FormData();
            formData.append("color", "red");

            const response = await this.$axios.$post(this.$globalValues.resourceServer + "/orders/html", formData, {
                responseType: "blob",
            });
            const blob = new Blob([response]);

            const url = window.URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.style.display = "none";
            a.href = url;
            a.download = "orders.pdf";

            document.body.appendChild(a);
            a.click();

            window.URL.revokeObjectURL(url);
            document.body.removeChild(a);
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
  