import { redirect } from "next/navigation";
import { currentUser } from "@proteles/next";
import { SignOutButton } from "@proteles/react";

// `proxy.ts` protects this route: an unauthenticated request is redirected to
// `/api/auth/login` before it renders. The page checks again anyway. A guard
// that lives only in the proxy fails open whenever the proxy does not run, and
// before 14.2.25 one request header could skip it (CVE-2025-29927).
export default async function Dashboard() {
  const user = await currentUser();
  if (!user) redirect("/api/auth/login?returnTo=%2Fdashboard");

  return (
    <main>
      <h1>Dashboard</h1>
      <p>
        Signed in as <strong>{user.email ?? user.sub}</strong>.
      </p>
      <p>This page is only reachable when authenticated.</p>
      <SignOutButton>Sign out</SignOutButton>
      <p>
        <a href="/">← Home</a>
      </p>
    </main>
  );
}
