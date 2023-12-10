<script>
export default {
    name: "LogoutPage",
    async asyncData() {
        return { redirect: "/" };
    },
    mounted() {
        document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 GMT; path=/";

        if (this.redirect) {
            this.$router.push(this.redirect);
        }
    },
}
</script>
