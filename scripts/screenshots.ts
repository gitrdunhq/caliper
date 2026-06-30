/**
 * Browser gate for `caliper part --serve` (Slice 5 live reclassify report).
 *
 * Captures the styled report at desktop + mobile, then drives the real
 * reclassify round trip through the browser UI (click → POST /reclassify →
 * reload) and captures the result, proving the JS + override write-back work
 * end to end. Headless; no manual steps.
 *
 * Run with the sidecar already serving on 127.0.0.1:12700:
 *   npx tsx scripts/screenshots.ts
 */
import { chromium, devices } from "playwright";
import { mkdirSync } from "node:fs";
import { join } from "node:path";

const URL = process.env.PART_SERVE_URL ?? "http://127.0.0.1:12700";
const OUT = join(process.cwd(), "screenshots");

const DESKTOP = { width: 1440, height: 900 };
const MOBILE = devices["iPhone 14"];

async function shot(page: import("playwright").Page, slug: string) {
  await page.screenshot({ path: join(OUT, `${slug}.png`), fullPage: true });
  console.log(`  saved ${slug}.png`);
}

async function main() {
  mkdirSync(OUT, { recursive: true });
  const browser = await chromium.launch({ headless: true });

  // --- desktop: initial state ---
  const desktop = await browser.newContext({ viewport: DESKTOP });
  const page = await desktop.newPage();
  await page.goto(URL, { waitUntil: "networkidle" });
  await shot(page, "part-serve-desktop");

  // --- mobile: initial state ---
  const mobile = await browser.newContext({ ...MOBILE });
  const mpage = await mobile.newPage();
  await mpage.goto(URL, { waitUntil: "networkidle" });
  await shot(mpage, "part-serve-mobile");

  // --- advisory suggester UI ---
  // Mock POST /suggest so the gate captures the chip rendering without a live model
  // (Ollama/OMLX may not be running in CI). The accept path reuses /reclassify, which
  // the round trip below already exercises against the real sidecar.
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
  await spage.locator("button.suggest").click();
  await spage.waitForSelector("#suggestions .chip");
  const chipCount = await spage.locator("#suggestions .chip").count();
  console.log(`  suggest chips rendered: ${chipCount}`);
  await shot(spage, "part-serve-desktop-suggest");

  // --- round trip: reclassify the first untiered file via the UI ---
  const untieredFile = page.locator("article.part.untiered li.file").first();
  const count = await untieredFile.count();
  if (count > 0) {
    const path = await untieredFile.locator("code.path").innerText();
    console.log(`  reclassifying untiered file: ${path}`);
    await untieredFile.locator("select.bucket").selectOption("business");
    await Promise.all([
      page.waitForLoadState("networkidle"),
      untieredFile.locator("button.save").click(),
    ]);
    await page.waitForSelector(".overrides:not(.empty)");
    await shot(page, "part-serve-desktop-after-reclassify");
    const badge = await page.locator(".overrides .ov").first().innerText();
    console.log(`  override badge now shows: ${badge.replace(/\s+/g, " ").trim()}`);
  } else {
    console.log("  no untiered parts to reclassify (skipped round trip)");
  }

  await browser.close();
  console.log("DONE");
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
