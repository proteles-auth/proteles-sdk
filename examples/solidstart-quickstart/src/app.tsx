import { Router } from "@solidjs/router";
import { FileRoutes } from "@solidjs/start/router";
import { Suspense } from "solid-js";
import { AuthProvider } from "@proteles/solid";

export default function App() {
  return (
    <AuthProvider>
      <Router
        root={(props) => (
          <main style={{ "font-family": "system-ui, sans-serif", "max-width": "640px", margin: "64px auto", padding: "0 16px" }}>
            <Suspense>{props.children}</Suspense>
          </main>
        )}
      >
        <FileRoutes />
      </Router>
    </AuthProvider>
  );
}
