import test from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";

test("package exports include stable root and ./types entrypoints", () => {
  const pkgPath = new URL("../package.json", import.meta.url);
  const pkg = JSON.parse(fs.readFileSync(pkgPath, "utf8"));

  assert.equal(pkg.name, "@encmind/skill-sdk");
  assert.ok(pkg.exports, "package.json must define exports");

  assert.deepEqual(pkg.exports["."], {
    types: "./dist/index.d.ts",
    default: "./dist/index.js",
  });

  assert.deepEqual(pkg.exports["./types"], {
    types: "./dist/types.d.ts",
    default: "./dist/types.js",
  });
});
