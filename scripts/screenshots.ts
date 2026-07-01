/**
 * Browser gate for the `caliper part --serve` SPA (scripts/part_ui).
 *
 * Captures the SPA at desktop + mobile, light + dark, then drives the real
 * reclassify round trip (click -> POST /reclassify -> re-render) and the
 * suggest-chip flow through the browser UI, proving the TS bundle + sidecar
 * work end to end. Also opens (without confirming) the P5 apply confirm
 * overlay, so a reviewer can eyeball it without mutating the target repo —
 * the real apply/rollback execution is verified separately against a
 * throwaway jj repo, not by this general-purpose visual gate.
 *
 * Headless; no manual steps. Run with the sidecar already serving a targeted
 * range on 127.0.0.1:12700 (`caliper part --repo ... --base ... --head ...
 * --serve`):
 *   npx tsx scripts/screenshots.ts
 */
import { mkdirSync } from "node:fs";
import { join } from "node:path";
import { chromium, devices, type Page } from "playwright";

const URL = process.env.PART_SERVE_URL ?? "http://127.0.0.1:12700";
const OUT = join(process.cwd(), "screenshots");

const DESKTOP = { width: 1440, height: 900 };
const MOBILE = devices["iPhone 14"];

async function shot(page: Page, slug: string) {
  await page.screenshot({ path: join(OUT, `${slug}.png`), fullPage: true });
  console.log(`  saved ${slug}.png`);
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });

  // --- initial cut render: desktop/mobile x light/dark ---
  for (const scheme of ["light", "dark"] as const) {
    const desktopCtx = await browser.newContext({ viewport: DESKTOP, colorScheme: scheme });
    const dpage = await desktopCtx.newPage();
    await dpage.goto(URL, { waitUntil: "networkidle" });
    await dpage.waitForSelector(".cut-header, .empty-state");
    await shot(dpage, `part-ui-desktop-${scheme}`);
    await desktopCtx.close();

    const mobileCtx = await browser.newContext({ ...MOBILE, colorScheme: scheme });
    const mpage = await mobileCtx.newPage();
    await mpage.goto(URL, { waitUntil: "networkidle" });
    await mpage.waitForSelector(".cut-header, .empty-state");
    await shot(mpage, `part-ui-mobile-${scheme}`);
    await mobileCtx.close();
  }

  // --- advisory suggester UI ---
  // Mock POST /suggest so the gate captures the chip rendering without a live
  // model (Ollama/OMLX may not be running in CI). Accepting a chip reuses
  // /reclassify, which the round trip below already exercises for real.
  const suggestCtx = await browser.newContext({ viewport: DESKTOP });
  await suggestCtx.route("**/suggest", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        configured: true,
        suggestions: [
          { glob: "**/lib/lambda/**", bucket: "business", note: "" },
          { glob: "**/cdk.json", bucket: "config", note: "" },
        ],
      }),
    }),
  );
  const spage = await suggestCtx.newPage();
  await spage.goto(URL, { waitUntil: "networkidle" });
  const suggestBtn = spage.locator('button[data-action="suggest"]');
  if ((await suggestBtn.count()) > 0) {
    await suggestBtn.click();
    await spage.waitForSelector("ul.chips .chip");
    const chipCount = await spage.locator("ul.chips .chip").count();
    console.log(`  suggest chips rendered: ${chipCount}`);
    await shot(spage, "part-ui-desktop-suggest");
  } else {
    console.log("  no suggest button (untargeted session) — skipped suggest gate");
  }
  await suggestCtx.close();

  // --- restack panel: generate script, then open (not confirm) the apply gate ---
  // Runs BEFORE the reclassify round trip below: writing an override touches
  // the target repo's working copy, and the safety gate correctly refuses to
  // restack over uncommitted changes — so this needs a clean working copy.
  const restackCtx = await browser.newContext({ viewport: DESKTOP });
  const rpage = await restackCtx.newPage();
  await rpage.goto(URL, { waitUntil: "networkidle" });
  const generateBtn = rpage.locator('button[data-action="generate-restack"]');
  if ((await generateBtn.count()) > 0) {
    await Promise.all([
      rpage.waitForResponse((r) => r.url().endsWith("/restack")),
      generateBtn.click(),
    ]);
    await rpage.waitForSelector(".rollback-header");
    await shot(rpage, "part-ui-desktop-restack-generated");

    await rpage.click('button[data-action="open-apply-confirm"]');
    await rpage.waitForSelector(".apply-confirm-overlay");
    await shot(rpage, "part-ui-desktop-apply-confirm");
    // Cancel — this gate never executes real jj surgery against an arbitrary
    // target repo; see tests/integration/test_part_e2e.py for the real round trip.
    await rpage.click('button[data-action="cancel-apply"]');
  } else {
    console.log("  no restack panel (untargeted session) — skipped restack gate");
  }
  await restackCtx.close();

  // --- round trip: reclassify the first file via the UI ---
  const desktop = await browser.newContext({ viewport: DESKTOP });
  const page = await desktop.newPage();
  await page.goto(URL, { waitUntil: "networkidle" });
  const firstRow = page.locator("li.file-row").first();
  if ((await firstRow.count()) > 0) {
    const path = await firstRow.getAttribute("data-path");
    console.log(`  reclassifying file: ${path}`);
    await firstRow.locator("select.bucket-select").selectOption("business");
    await Promise.all([
      page.waitForResponse((r) => r.url().endsWith("/reclassify")),
      firstRow.locator('button[data-action="reclassify"]').click(),
    ]);
    await page.waitForSelector(".overrides:not(.empty)");
    await shot(page, "part-ui-desktop-after-reclassify");
    const badge = await page.locator(".overrides .ov").first().innerText();
    console.log(`  override badge now shows: ${badge.replace(/\s+/g, " ").trim()}`);
  } else {
    console.log("  no files to reclassify (untargeted session) — skipped round trip");
  }

  await browser.close();
  console.log("DONE");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
