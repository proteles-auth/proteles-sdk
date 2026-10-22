#!/usr/bin/env node
// Generates the Management SDK's WIRE types from spec/openapi.json.
//
// The sibling generator, `generate-management-enums.mjs`, deliberately stopped
// at enums, and said why: "generating interfaces would either replace a
// deliberate API or add a parallel one nobody asked for". That reasoning held
// for the SDK's *public* camelCase surface, which is a deliberate API. It never
// applied to the wire shapes, which are not an API at all — they are a
// transcript of what the server sends, and a hand-written transcript is exactly
// the thing that drifts.
//
// So: snake_case interfaces, one per component schema, mapped into the public
// types by hand as they already are. The mapping layer survives generation
// rather than being replaced by it.
//
// **Generating from the spec is only safe because the spec is checked against
// the server.** Proteles' server tests validate a real response body
// against its schema at seventeen operations, covering every
// schema the SDK maps. Without that this generator would launder a
// hand-written document into a compiler-enforced type — which is the objection
// that kept it unwritten, and the objection that got answered rather than
// argued away. This repository reads a copy of that checked spec,
// spec/openapi.json, pinned to the server commit named in spec/SERVER_COMMIT.
//
//   node tools/generate-management-wire.mjs           # write the file
//   node tools/generate-management-wire.mjs --check   # fail if it is stale
//   node tools/generate-management-wire.mjs --self-test
import { readFileSync, writeFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const SPEC = path.join(ROOT, "spec/openapi.json");
const OUT = path.join(ROOT, "packages/management/src/generated/wire.ts");

/**
 * The keywords this generator understands.
 *
 * Same discipline as the server's own OpenAPI validation: refuse
 * on anything unknown rather than ignore it. A generator that silently skips a keyword emits a type that
 * claims more than the document says, and the claim is then enforced by tsc on
 * every consumer — a stronger lie than the hand-written type it replaced.
 */
const KNOWN = new Set([
  "$ref", "allOf", "oneOf", "type", "properties", "required", "items", "enum", "const",
  "additionalProperties", "description", "format", "example", "nullable",
  "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum",
  "minLength", "maxLength", "minItems", "maxItems", "uniqueItems", "default",
  "title", "deprecated", "readOnly", "writeOnly", "pattern",
]);

/**
 * Keywords that are known and deliberately produce nothing.
 *
 * A value constraint is not a type constraint: `pattern`, `minLength` and the
 * numeric bounds narrow which strings and numbers are legal, and TypeScript has
 * no way to say that. They belong in `KNOWN` so the generator does not refuse a
 * document that uses them, and they are listed here so "understood, no effect"
 * is written down rather than being an accident of the switch below. The
 * validator DOES enforce them at runtime, which is where that check belongs.
 */
export const NO_TYPE_EFFECT = new Set([
  "pattern", "minLength", "maxLength", "minItems", "maxItems", "uniqueItems",
  "minimum", "maximum", "exclusiveMinimum", "exclusiveMaximum", "format",
  "example", "description", "default", "title", "deprecated", "readOnly",
  "writeOnly",
]);

const isExtension = (k) => k.startsWith("x-");

/** A JSON string as a TypeScript string literal. */
const lit = (v) => (v === null ? "null" : typeof v === "string" ? JSON.stringify(v) : JSON.stringify(v));

/** Wrap a doc comment, or return "" when there is nothing to say. */
export function docComment(text, indent) {
  if (!text) return "";
  const words = String(text).replace(/\s+/g, " ").trim();
  if (!words) return "";
  const width = 76 - indent.length;
  const lines = [];
  let line = "";
  for (const w of words.split(" ")) {
    if (line && line.length + 1 + w.length > width) {
      lines.push(line);
      line = w;
    } else {
      line = line ? `${line} ${w}` : w;
    }
  }
  if (line) lines.push(line);
  if (lines.length === 1) return `${indent}/** ${lines[0]} */\n`;
  return `${indent}/**\n${lines.map((l) => `${indent} * ${l}`).join("\n")}\n${indent} */\n`;
}

/**
 * A schema node as a TypeScript type expression.
 *
 * `refName` decides what a `$ref` becomes; it is a parameter rather than a
 * constant so the self-test can drive this without a components section.
 */
export function typeExpr(schema, indent, refName = (n) => n) {
  const s = schema || {};
  for (const k of Object.keys(s)) {
    if (!KNOWN.has(k) && !isExtension(k)) {
      throw new Error(`the spec uses "${k}", which this generator does not implement — extend it rather than emitting a type that ignores it`);
    }
  }

  if (s.$ref) return refName(s.$ref.split("/").pop());

  // Only ever a single-$ref wrapper in this document, used to hang a
  // description on a reference. An intersection is right for the general case
  // and identical to the reference for this one.
  if (Array.isArray(s.allOf)) {
    const parts = s.allOf.map((p) => typeExpr(p, indent, refName));
    return parts.length === 1 ? parts[0] : parts.join(" & ");
  }

  // A union. The document reaches for this where a *referenced object* is
  // nullable — `{"oneOf": [{"$ref": ...}, {"type": "null"}]}` — because the
  // `type: [..., "null"]` spelling has nowhere to put the reference and
  // `allOf` + `nullable` would say "this thing, and also null", which is not a
  // thing. TypeScript's union is exact for `oneOf` only when the members are
  // disjoint, and in this document they are: a reference and a null.
  if (Array.isArray(s.oneOf)) {
    return uniqueUnion(s.oneOf.map((p) => typeExpr(p, indent, refName)));
  }

  // `const` first: it is the narrowest thing a node can say.
  if ("const" in s) return lit(s.const);

  const types = Array.isArray(s.type) ? s.type : s.type ? [s.type] : [];
  const nullable = types.includes("null") || s.nullable === true;
  const base = types.filter((t) => t !== "null");

  let expr;
  if (s.enum) {
    // The enum carries its own null member in this document rather than
    // relying on the type list, so filter it out and let `nullable` add it
    // back exactly once.
    const members = s.enum.filter((v) => v !== null).map(lit);
    if (s.enum.includes(null)) expr = members.length ? members.join(" | ") : "null";
    else expr = members.join(" | ");
    if (s.enum.includes(null)) return uniqueUnion([expr, "null"]);
  } else if (base.length === 0) {
    // `{"type": "null"}` is the null type itself, not an absent one — it is how
    // a `oneOf` says "or nothing here". Leaving `expr` empty lets the nullable
    // branch below contribute the only member; `uniqueUnion` drops the blank.
    // A node with no `type` at all is genuinely unconstrained and stays unknown.
    expr = types.includes("null") ? "" : "unknown";
  } else {
    expr = uniqueUnion(base.map((t) => scalar(t, s, indent, refName)));
  }
  return nullable ? uniqueUnion([expr, "null"]) : expr;
}

const uniqueUnion = (parts) => [...new Set(parts.filter(Boolean))].join(" | ");

function scalar(t, s, indent, refName) {
  switch (t) {
    case "string":
      return "string";
    case "integer":
    case "number":
      return "number";
    case "boolean":
      return "boolean";
    case "array":
      return s.items ? `${maybeParen(typeExpr(s.items, indent, refName))}[]` : "unknown[]";
    case "object":
      return objectExpr(s, indent, refName);
    default:
      throw new Error(`unknown type "${t}"`);
  }
}

/** A union inside `[]` needs parentheses, and a bare name does not. */
const maybeParen = (e) => (/[|&]/.test(e) ? `(${e})` : e);

function objectExpr(s, indent, refName) {
  const props = s.properties || {};
  const names = Object.keys(props);
  if (names.length === 0) {
    // `additionalProperties` as a schema is the map case; `true` with no
    // properties is a free-form object.
    if (s.additionalProperties && typeof s.additionalProperties === "object") {
      return `Record<string, ${typeExpr(s.additionalProperties, indent, refName)}>`;
    }
    return s.additionalProperties === false ? "Record<string, never>" : "Record<string, unknown>";
  }
  const inner = indent + "  ";
  const required = new Set(s.required || []);
  const body = names
    .map((n) => {
      const p = props[n];
      const opt = required.has(n) ? "" : "?";
      return `${docComment(p.description, inner)}${inner}${key(n)}${opt}: ${typeExpr(p, inner, refName)};`;
    })
    .join("\n");
  const extra =
    s.additionalProperties && typeof s.additionalProperties === "object"
      ? `\n${inner}[key: string]: ${typeExpr(s.additionalProperties, inner, refName)};`
      : "";
  return `{\n${body}${extra}\n${indent}}`;
}

/** A property name that is not a plain identifier has to be quoted. */
const key = (n) => (/^[A-Za-z_$][A-Za-z0-9_$]*$/.test(n) ? n : JSON.stringify(n));

export function render(spec) {
  const schemas = (spec.components && spec.components.schemas) || {};
  const names = Object.keys(schemas).sort();
  const out = [
    "// GENERATED by tools/generate-management-wire.mjs - do not edit.",
    "//",
    "// The snake_case shapes the server actually sends and accepts, one per",
    "// schema in spec/openapi.json. The public camelCase API in ../types.ts",
    "// is mapped onto these by hand: generation replaces the transcript, not the",
    "// interface a caller sees.",
    "//",
    "// Optionality here is the SPEC's `required`, which means \"always present in",
    "// this payload\" and not \"non-optional on the resource\" — which is why",
    "// `TenantSummary` and `TenantDetail` are two types rather than one type with",
    "// optional members.",
    "",
  ];
  for (const name of names) {
    const s = schemas[name];
    const doc = docComment(s.description, "");
    const expr = typeExpr(s, "");
    if (expr.startsWith("{")) {
      out.push(`${doc}export interface ${name} ${expr}\n`);
    } else {
      out.push(`${doc}export type ${name} = ${expr};\n`);
    }
  }
  return out.join("\n").replace(/\n{3,}/g, "\n\n");
}

function selfTest() {
  let pass = 0, fail = 0;
  const ok = (m) => { console.log(`  \x1b[32m✓\x1b[0m ${m}`); pass++; };
  const no = (m, d) => { console.log(`  \x1b[31m✗\x1b[0m ${m}`); if (d) console.log(`      ${d}`); fail++; };
  const eq = (name, got, want) => (got === want ? ok(name) : no(name, `got ${JSON.stringify(got)}, want ${JSON.stringify(want)}`));

  console.log("== management wire generator ==");
  eq("a plain string", typeExpr({ type: "string" }, ""), "string");
  eq("integer becomes number", typeExpr({ type: "integer" }, ""), "number");
  // The spelling this document actually uses for nullability, 43 times.
  eq("a 3.1 nullable union", typeExpr({ type: ["string", "null"] }, ""), "string | null");
  eq("the 3.0 nullable spelling too", typeExpr({ type: "string", nullable: true }, ""), "string | null");
  eq("an array of scalars", typeExpr({ type: "array", items: { type: "string" } }, ""), "string[]");
  // Without the parentheses this would parse as `string | (null[])`.
  eq("an array of a union is parenthesised",
    typeExpr({ type: "array", items: { type: ["string", "null"] } }, ""), "(string | null)[]");
  eq("an enum is a closed union",
    typeExpr({ type: "string", enum: ["a", "b"] }, ""), '"a" | "b"');
  eq("an enum carrying null adds null exactly once",
    typeExpr({ type: ["string", "null"], enum: ["a", null] }, ""), '"a" | null');
  eq("a const is a literal", typeExpr({ type: "string", const: "TXT" }, ""), '"TXT"');
  eq("a $ref is the named type", typeExpr({ $ref: "#/components/schemas/Foo" }, ""), "Foo");
  eq("a single-member allOf is its member",
    typeExpr({ allOf: [{ $ref: "#/components/schemas/Foo" }] }, ""), "Foo");
  // The reason `oneOf` exists here at all: a nullable *reference* cannot be
  // spelled with `type: [..., "null"]`.
  eq("a oneOf is a union",
    typeExpr({ oneOf: [{ $ref: "#/components/schemas/Foo" }, { type: "null" }] }, ""), "Foo | null");
  eq("a oneOf of scalars is a union too",
    typeExpr({ oneOf: [{ type: "string" }, { type: "integer" }] }, ""), "string | number");
  // And inside an array, where a bare union would parse as `Foo | (null[])`.
  eq("an array of a oneOf is parenthesised",
    typeExpr({ type: "array", items: { oneOf: [{ $ref: "#/components/schemas/Foo" }, { type: "null" }] } }, ""),
    "(Foo | null)[]");
  eq("a free-form object", typeExpr({ type: "object" }, ""), "Record<string, unknown>");
  eq("a closed object with no properties admits nothing",
    typeExpr({ type: "object", additionalProperties: false }, ""), "Record<string, never>");
  eq("a map", typeExpr({ type: "object", additionalProperties: { type: "integer" } }, ""),
    "Record<string, number>");

  // Optionality is the spec's `required`, and getting it backwards is the
  // failure that would matter most: a required field typed optional makes every
  // consumer write a needless guard, and an optional field typed required is a
  // runtime undefined tsc has promised cannot happen.
  const obj = typeExpr({ type: "object", required: ["a"], properties: { a: { type: "string" }, b: { type: "string" } } }, "");
  eq("required and optional are distinguished", obj, "{\n  a: string;\n  b?: string;\n}");

  // The refusal. A generator that ignores what it cannot read emits a type that
  // claims more than the document says.
  let threw = false;
  try { typeExpr({ type: "number", multipleOf: 3 }, ""); } catch { threw = true; }
  threw ? ok("an unimplemented keyword is refused, not ignored") : no("an unimplemented keyword is refused");
  let threwExt = false;
  try { typeExpr({ type: "string", "x-note": "hi" }, ""); } catch { threwExt = true; }
  threwExt ? no("an x- extension is skipped") : ok("an x- extension is skipped, not refused");

  console.log();
  if (fail) { console.log(`${fail} of ${pass + fail} cases FAILED`); process.exit(1); }
  console.log(`all ${pass} cases passed`);
  process.exit(0);
}

const RUN_DIRECTLY = process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url);
if (RUN_DIRECTLY) {
  if (process.argv[2] === "--self-test") selfTest();
  const spec = JSON.parse(readFileSync(SPEC, "utf8"));
  const text = render(spec);
  if (process.argv[2] === "--check") {
    let current = "";
    try { current = readFileSync(OUT, "utf8"); } catch { /* absent counts as stale */ }
    if (current !== text) {
      console.error("packages/management/src/generated/wire.ts is stale — run:");
      console.error("  node tools/generate-management-wire.mjs");
      process.exit(1);
    }
    console.log("\x1b[32m✓\x1b[0m generated wire types match the spec");
    process.exit(0);
  }
  writeFileSync(OUT, text);
  console.log(`wrote ${path.relative(ROOT, OUT)} (${text.split("\n").length} lines)`);
}
