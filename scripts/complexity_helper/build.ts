/**
 * Build the JS/TS maintainability helper into a committed bundle (#441).
 *
 * Run via `npm run build:complexity-helper` or `make complexity-helper`.
 * Output is package data — complexity_runner.py invokes it with the system
 * `node`; typhonjs-escomplex is inlined, so no npm install at runtime.
 */

import { build } from "esbuild";
import { mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(
  here, "..", "..", "src", "caliper", "plugins", "_runners", "complexity_helper_dist",
);

mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: [join(here, "mi.ts")],
  bundle: true,
  minify: true,
  platform: "node",
  format: "cjs",
  target: "es2022",
  // .cjs: a scanned repo (or this one) may carry `"type": "module"` in an
  // ancestor package.json, which would force a .js file to be parsed as ESM.
  outfile: join(outDir, "mi.cjs"),
});

console.log(`built complexity helper -> ${outDir}`);
