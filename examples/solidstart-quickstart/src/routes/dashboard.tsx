import { A } from "@solidjs/router";
import { SignOutButton, useUser } from "@proteles/solid";

// This route is protected by `src/middleware.ts`: an unauthenticated request is
// redirected to /api/auth/login before it ever renders.
export default function Dashboard() {
  const { user } = useUser();

  return (
    <div>
      <h1>Dashboard</h1>
      <p>Signed in as <strong>{user()?.email ?? user()?.sub}</strong>.</p>
      <p>This page is only reachable when authenticated.</p>
      <SignOutButton>Sign out</SignOutButton>
      <p><A href="/">← Home</A></p>
    </div>
  );
}
