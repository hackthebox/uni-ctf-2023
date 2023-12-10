<template>
  <div class="login-card fill">
      <h2>You must log-in using <b>Phantomfeed</b></h2>
      <hr>
      <br>
      <a :href="auth + '/oauth2/auth?client_id=' + clientid + '&redirect_url=' + market + '/callback'" class="login-button">
          <img src="/icon.png" width="50" height="50">&nbsp;Log-in
      </a>
      <br>
      <br>
  </div>
</template>

<script>
export default {
  name: "LoginCard",
  props: {
      auth: String,
      market: String,
      clientid: String
  }
}
</script>