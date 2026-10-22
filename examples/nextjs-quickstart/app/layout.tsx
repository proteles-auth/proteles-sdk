import type { ReactNode } from "react";
import { currentUser } from "@proteles/next";
import { AuthProvider } from "@proteles/react";

export const metadata = {
  title: "Proteles quickstart",
  description: "Auth in ~5 minutes with @proteles/next + @proteles/react",
};

export default async function RootLayout({ children }: { children: ReactNode }) {
  // Read the user server-side (from the httpOnly cookie) and seed the provider,
  // so the first paint already reflects the real auth state — no signed-out
  // flash. `AuthProvider` still revalidates against /api/auth/me on mount.
  const user = await currentUser();

  return (
    <html lang="en">
      <body style={{ fontFamily: "system-ui, sans-serif", maxWidth: 640, margin: "64px auto", padding: "0 16px" }}>
        <AuthProvider initialUser={user}>{children}</AuthProvider>
      </body>
    </html>
  );
}
