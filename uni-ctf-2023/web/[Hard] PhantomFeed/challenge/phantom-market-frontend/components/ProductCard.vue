<template>
    <div class="p-3">
       <img class="product-img mb-3" :src="'/backend/static/' + product.image_link">
       <h3>{{ product.title }}</h3>
       <hr>
       <span class="price">{{ product.price }}</span>
       <br>
       <NuxtLink class="underline mt-2" :to="'/product/' + product.id">View more</NuxtLink>
    </div>
</template>

<script>
export default {
    name: "ProductCard",
    props: {
        product: Object
    }
}
</script>