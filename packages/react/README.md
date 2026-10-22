# @proteles/react

> **You need a Proteles account.** Proteles is a hosted sign-in service, and this
> package is a client for it: without an account it does nothing.
> [Sign up for free on proteles.com](https://proteles.com/signup), then register your app to get its
> issuer, client ID and secret.

Drop-in React components and hooks for Proteles authentication.

They talk **only** to the [`@proteles/next`](https://www.npmjs.com/package/@proteles/next) BFF's `/api/auth/*` routes —
never to the authorization server directly — so no secrets or tokens ever reach
the browser. Pair this with `@proteles/next` in the same app.

## Install

```bash
npm install @proteles/react @proteles/next @proteles/js
```

## The five-minute setup

```tsx
// app/layout.tsx
import { AuthProvider } from "@proteles/react";

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html>
      <body>
        <AuthProvider>{children}</AuthProvider>
      </body>
    </html>
  );
}
```

```tsx
// app/page.tsx
"use client";
import { SignedIn, SignedOut, SignInButton, UserButton, useUser } from "@proteles/react";

export default function Home() {
  const { user } = useUser();
  return (
    <>
      <SignedOut>
        <SignInButton />
      </SignedOut>
      <SignedIn>
        Hi {user?.email} <UserButton />
      </SignedIn>
    </>
  );
}
```

That's it — `<AuthProvider>` fetches `/api/auth/me`, and the components react to
the result.

## API

### `<AuthProvider>`

Wrap your app once. Props:

- `basePath?` — the BFF mount path. Defaults to `NEXT_PUBLIC_PROTELES_BASE_PATH`
  or `/api/auth`.
- `initialUser?` — a server-known user (from `currentUser()` in `@proteles/next`)
  to avoid a signed-out flash on first paint. `undefined` = fetch on mount,
  `null` = known signed-out, an object = known signed-in.

### Hooks

- `useUser()` → `{ user, isLoading, isAuthenticated, isUnavailable }`.
- `useAuth()` → the above plus `signIn(opts?)`, `signUp(opts?)`,
  `signOut(opts?)`, `reload()`, `basePath`.

### Components

| Component | Renders |
| --- | --- |
| `<SignedIn>` | children when a user is signed in |
| `<SignedOut>` | children when no user is signed in |
| `<Protect fallback={…}>` | children when signed in, else `fallback` (nothing while loading) |
| `<SignInButton returnTo? connection?>` | a button that starts login (`connection` picks a social provider, e.g. `"google"`) |
| `<SignUpButton returnTo?>` | a button that starts sign-up ([below](#sign-up)) |
| `<SignOutButton returnTo?>` | a button that logs out |
| `<UserButton>` | the user's name/email + a sign-out control |

`SignInButton`/`SignUpButton`/`SignOutButton`/`UserButton` are unstyled by
design — pass `className` and style them to match your app.

### Sign-up

`signUp({ returnTo })` and `<SignUpButton>` send the person through
`/api/auth/signup` to the workspace's hosted sign-up page. They give their email
address, follow the link they are mailed, choose a password, and come back to
`returnTo` (by default the page they were on) signed in, as after a sign-in.
Where the workspace has not opened its sign-up page, they see the ordinary
sign-in page instead.

It takes no `connection`. For a sign-up through a social provider, use
`signIn({ connection })`: a first sign-in through it makes an account where
the workspace allows that.

### When the sign-in service is busy

While the authorization server is too busy to refresh a session, the BFF's
`/api/auth/me` answers `503` and keeps the session cookie. That — or a `429`, a
`408`, any other `5xx`, or no answer at all — is read as "could not tell", not
as signed out: `user` stays the last one known (`isLoading` stays `true` if no
answer has come yet), `isUnavailable` turns `true`, and `/me` is asked again
after the server's `Retry-After` (capped at an hour) or, when it named none,
after 2 s, 4 s, 8 s and so on up to 30 s. The next answer clears
`isUnavailable`. A `401`, or `{ authenticated: false }`, still means signed out,
as before.

`<SignedIn>` keeps rendering for the known user meanwhile; read `isUnavailable`
to tell them the service is busy. An `<AuthProvider>` that unmounts stops
asking.

## Notes

- All components are client components (`"use client"`). Import them into client
  components, or render them inside your `<AuthProvider>` tree.
- `useUser`/`useAuth` throw if used outside `<AuthProvider>` — a clear error
  instead of a silent null.
- A `/me` that refuses or cannot be read degrades to the signed-out state, and
  a busy or unreachable one to the last known state (above); the components
  never throw on a network error.

## Develop

```bash
npm install      # from the repository root
npm run build    # tsc -> dist (preserves the "use client" directives)
npm test         # tsx + node:test (pure logic + react-dom/server render tests)
```
