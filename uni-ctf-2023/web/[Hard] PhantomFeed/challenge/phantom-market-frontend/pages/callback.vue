<template>
    <div class="loading-container">
        <img class="loading-img" src="/icon.png">
    </div>
</template>

<script>
export default {
    name: "CallbackPage",
    async mounted() {
        if (!this.$route.query.authorization_code) {
            this.$router.push("/");
        }

        this.getToken();
    },
    methods: {
        setCookie(cookieName, cookieValue, secondsToExpire) {
            const expirationDate = new Date();
            expirationDate.setTime(expirationDate.getTime() + secondsToExpire * 1000);
            const cookieString = `${cookieName}=${cookieValue}; SameSite=Strict; expires=${expirationDate.toUTCString()}; path=/`;
            document.cookie = cookieString;
        },
        async getToken() {
            try {
                const response = await this.$axios.$get(this.$globalValues.authServer + `/oauth2/token?authorization_code=${this.$route.query.authorization_code}&client_id=${this.$globalValues.clientId}&redirect_url=${this.$globalValues.marketServer}/callback`);
                this.setCookie("access_token", response.access_token, response.expires_in);
                this.$router.push("/");
            }
            catch (err) {
                console.log(err);
            }
        }
    }
}
</script>