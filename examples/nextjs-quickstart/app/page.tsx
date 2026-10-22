"use client";

import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/react";

export default function Home() {
  const { user, isLoading } = useUser();

  return (
    <main>
      <h1>Proteles quickstart</h1>
      <p>A Next.js app with authentication in three files. See the README.</p>

      {isLoading ? (
        <p>Loading…</p>
      ) : (
        <>
          <SignedOut>
            <p>You are signed out.</p>
            <SignInButton>Sign in</SignInButton>
          </SignedOut>

          <SignedIn>
            <p>
              Hi <strong>{user?.email ?? user?.preferredUsername ?? user?.sub}</strong> 👋
            </p>
            <UserButton />
            <p>
              <a href="/dashboard">Visit the protected dashboard →</a>
            </p>
          </SignedIn>
        </>
      )}
    </main>
  );
}
