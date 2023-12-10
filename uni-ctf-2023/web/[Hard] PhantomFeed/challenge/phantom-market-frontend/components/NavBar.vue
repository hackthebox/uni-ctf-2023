<template>
    <div>
        <nav class="navbar navbar-expand-lg navbar-dark navbar-custom fixed-top">
            <div class="container-fluid">
                <a class="navbar-brand text-white" href="javascript:void();">
                    <img src="/icon.png" width="50" height="50">
                    PhantomMarket
                </a>
                <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#navbarNav"
                    aria-controls="navbarNav" aria-expanded="false" aria-label="Toggle navigation">
                    <span class="navbar-toggler-icon"></span>
                </button>
                <div class="collapse navbar-collapse" id="navbarNav">
                    <ul class="navbar-nav">
                        <li class="nav-item">
                            <NuxtLink class="nav-link underline" to="/">All products</NuxtLink>
                        </li>
                        <li class="nav-item">
                            <a class="nav-link underline" :href="phantomFeedUrl + '/'">PhantomFeed</a>
                        </li>
                        <li v-if="userData.user_type == 'administrator'" class="nav-item">
                            <NuxtLink class="nav-link underline" to="/orders">Orders</NuxtLink>
                        </li>
                    </ul>
                </div>
                <div class="nav-item-right">
                    <span>
                        <span class="text-white">{{ userData.username }}</span>
                        &nbsp;
                        <NuxtLink class="underline" to="/logout">Log-out</NuxtLink>
                    </span>
                </div>
            </div>
        </nav>
    </div>
</template>

<script>
export default {
    name: "NavBar",
    props: {
        userData: null,
        phantomFeedUrl: null
    }
}
</script>