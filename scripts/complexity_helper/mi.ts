/**
 * JS/TS maintainability-index helper (#441).
 *
 * Usage: node mi.cjs <file> [<file> ...]
 * Stdout: JSON array of {file, mi} — `file` echoed exactly as given, `mi`
 * rescaled from typhonjs-escomplex's 171-point MI to radon's 0-100 scale so
 * the Python runner formats JS/TS and Python scores identically.
 *
 * Fail-open per file: unreadable or unparseable files are skipped, never
 * fatal. The process always exits 0 with valid JSON on stdout.
 *
 * Source for the committed bundle
 * src/caliper/plugins/_runners/complexity_helper_dist/mi.cjs — rebuild with
 * `make complexity-helper` and recommit whenever this file changes.
 */
import { readFileSync } from 'node:fs';

import escomplex from 'typhonjs-escomplex';

interface FileMi {
  file: string;
  mi: number;
}

const out: FileMi[] = [];
for (const file of process.argv.slice(2)) {
  try {
    const source = readFileSync(file, 'utf8');
    const report = escomplex.analyzeModule(source);
    const rescaled = (report.maintainability * 100) / 171;
    const mi = Math.max(0, Math.min(100, rescaled));
    out.push({ file, mi: Math.round(mi * 10) / 10 });
  } catch {
    // fail-open: skip files that cannot be read or parsed
  }
}
process.stdout.write(JSON.stringify(out));
