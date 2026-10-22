<script setup lang="ts">
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/vue";

const { user, isLoading } = useUser();
</script>

<template>
  <div>
    <h1>Proteles Nuxt quickstart</h1>
    <p>A Nuxt app with authentication in three files. See the README.</p>

    <p v-if="isLoading">Loading…</p>
    <template v-else>
      <SignedOut>
        <p>You are signed out.</p>
        <SignInButton>Sign in</SignInButton>
      </SignedOut>

      <SignedIn>
        <p>Hi <strong>{{ user?.email ?? user?.preferredUsername ?? user?.sub }}</strong> 👋</p>
        <UserButton />
        <p><NuxtLink to="/dashboard">Visit the protected dashboard →</NuxtLink></p>
      </SignedIn>
    </template>
  </div>
</template>
