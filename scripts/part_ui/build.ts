/**
 * Build the `caliper part --serve` SPA into a committed bundle.
 *
 * Run via `npm run build:part-ui` or `bash scripts/build_part_ui.sh` (P6).
 * Output is package data — `src/caliper/cli/part_serve.py:load_assets()`
 * reads it straight off disk, no Node needed at runtime.
 */

import { build } from "esbuild";
import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const outDir = join(here, "..", "..", "src", "caliper", "cli", "part_ui_dist");

mkdirSync(outDir, { recursive: true });

await build({
  entryPoints: [join(here, "app.ts")],
  bundle: true,
  minify: true,
  format: "iife",
  target: "es2022",
  outfile: join(outDir, "part_ui.js"),
});

await build({
  entryPoints: [join(here, "styles.css")],
  bundle: true,
  minify: true,
  outfile: join(outDir, "part_ui.css"),
});

copyFileSync(join(here, "index.html"), join(outDir, "index.html"));

console.log(`built part_ui -> ${outDir}`);
