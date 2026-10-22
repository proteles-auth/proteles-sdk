//! Minimal ambient declaration for the one Next.js API we touch dynamically,
//! `next/headers.cookies()`. Declaring it here lets `@proteles/next` build and
//! typecheck without a hard dependency on `next` (it is an optional peer). In a
//! real Next app the actual module is used at runtime; `cookies()` is sync on
//! Next 14 and async on Next 15, so we type it as either and `await` it.

declare module "next/headers" {
  interface ProtelesReadonlyCookies {
    get(name: string): { name: string; value: string } | undefined;
  }
  export function cookies(): Promise<ProtelesReadonlyCookies> | ProtelesReadonlyCookies;
}
