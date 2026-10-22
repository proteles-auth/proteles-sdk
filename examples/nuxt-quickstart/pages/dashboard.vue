<script setup lang="ts">
import { SignOutButton, useUser } from "@proteles/vue";

// This route is protected by `server/middleware/proteles.ts`: an
// unauthenticated request is redirected to /api/auth/login before it renders.
const { user } = useUser();
</script>

<template>
  <div>
    <h1>Dashboard</h1>
    <p>Signed in as <strong>{{ user?.email ?? user?.sub }}</strong>.</p>
    <p>This page is only reachable when authenticated.</p>
    <SignOutButton>Sign out</SignOutButton>
    <p><NuxtLink to="/">← Home</NuxtLink></p>
  </div>
</template>
