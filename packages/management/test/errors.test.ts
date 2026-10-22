//! `ManagementErrorCode` names every `error` slug the published spec declares.
//!
//! The union is hand-written, and its doc comment says it is every slug
//! `/api/v1` emits. It was missing `rate_limited`, which the limiter sends from
//! every operation. That slug lives in the 429's own schema, apart from the
//! three handler error schemas the other eleven come from. Nothing generated or
//! checked the union, so this test reads both sides: the slugs every 4xx and 5xx
//! body in `spec/openapi.json` enumerates, and the members of the union in
//! `src/errors.ts`, and holds them equal.
//!
//! A source scan rather than a type-level assertion, because the spec side is
//! only known at run time, and a type test would need the schema names typed
//! out by hand, which is the list that went stale.

import { readFileSync } from "node:fs";
import { test } from "node:test";
import assert from "node:assert/strict";

type Node = { $ref?: string; [key: string]: unknown };
type Schema = Node & {
  properties?: Record<string, Node>;
  allOf?: Node[];
  oneOf?: Node[];
  anyOf?: Node[];
  enum?: unknown[];
  const?: unknown;
};

const spec = JSON.parse(readFileSync(new URL("../../../spec/openapi.json", import.meta.url), "utf8")) as {
  paths: Record<string, Record<string, { responses?: Record<string, Node> }>>;
};

function deref(node: Node | undefined): Schema | undefined {
  let n: Node | undefined = node;
  while (n?.$ref) {
    const ref: string = n.$ref;
    n = ref
      .replace(/^#\//, "")
      .split("/")
      .reduce<unknown>((o, k) => (o as Record<string, unknown>)[k], spec) as Node | undefined;
    assert.ok(n, `${ref} does not resolve`);
  }
  return n as Schema | undefined;
}

/** Every `error` slug an error response body in the spec enumerates. */
function specErrorCodes(): Set<string> {
  const codes = new Set<string>();
  const visit = (node: Node | undefined, where: string): void => {
    const schema = deref(node);
    if (!schema) return;
    for (const branch of [...(schema.allOf ?? []), ...(schema.oneOf ?? []), ...(schema.anyOf ?? [])]) visit(branch, where);
    const error = deref(schema.properties?.["error"]);
    if (!error) return;
    const values = error.enum ?? (error.const !== undefined ? [error.const] : undefined);
    // An error body whose slug is an open string would say nothing here, and
    // this test would pass without reading it.
    assert.ok(values, `${where}: the error body's \`error\` is not enumerated`);
    for (const v of values) codes.add(String(v));
  };
  for (const [path, item] of Object.entries(spec.paths)) {
    for (const [method, op] of Object.entries(item)) {
      for (const [status, response] of Object.entries(op?.responses ?? {})) {
        if (!/^[45]/.test(status)) continue;
        const content = (deref(response)?.["content"] ?? {}) as Record<string, { schema?: Node }>;
        for (const media of Object.values(content)) visit(media.schema, `${method.toUpperCase()} ${path} ${status}`);
      }
    }
  }
  return codes;
}

/** The string literals in `export type ManagementErrorCode = … ;` in `src/errors.ts`. */
function unionMembers(): Set<string> {
  const source = readFileSync(new URL("../src/errors.ts", import.meta.url), "utf8");
  const body = /export type ManagementErrorCode =([^;]*);/.exec(source);
  assert.ok(body, "src/errors.ts declares `export type ManagementErrorCode = … ;`");
  return new Set([...body[1]!.matchAll(/"([^"]+)"/g)].map((m) => m[1]!));
}

test("ManagementErrorCode names exactly the error slugs the spec declares", () => {
  const declared = specErrorCodes();
  const union = unionMembers();
  // Positive controls, so an empty walk or an empty scan cannot pass: one slug
  // a handler schema declares, and the one only the limiter's schema does.
  assert.ok(declared.has("not_found") && declared.has("rate_limited"), `the spec walk found ${[...declared].join(", ")}`);
  assert.ok(union.has("invalid_request"), `the source scan found ${[...union].join(", ")}`);

  const missing = [...declared].filter((c) => !union.has(c)).sort();
  const extra = [...union].filter((c) => !declared.has(c)).sort();
  assert.deepEqual(missing, [], "slugs the spec declares and ManagementErrorCode does not name");
  assert.deepEqual(extra, [], "slugs ManagementErrorCode names and the spec does not declare");
});
