import { A } from "@solidjs/router";
import { Show } from "solid-js";
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/solid";

export default function Home() {
  const { user, isLoading } = useUser();

  return (
    <div>
      <h1>Proteles SolidStart quickstart</h1>
      <p>A SolidStart app with authentication in three files. See the README.</p>

      <Show when={!isLoading()} fallback={<p>Loading…</p>}>
        <SignedOut>
          <p>You are signed out.</p>
          <SignInButton>Sign in</SignInButton>
        </SignedOut>

        <SignedIn>
          <p>
            Hi <strong>{user()?.email ?? user()?.preferredUsername ?? user()?.sub}</strong> 👋
          </p>
          <UserButton />
          <p><A href="/dashboard">Visit the protected dashboard →</A></p>
        </SignedIn>
      </Show>
    </div>
  );
}
