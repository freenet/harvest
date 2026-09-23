// Load the Harvest web app from a rehearsal node in headless Chromium and
// record the app's console until the delegate migration walk has reported.
//
// Usage: node load-ui.js <http-url-of-the-harvest-page> <out.log> [max-seconds]
//
// Exits 0 once the walk's summary line ("delegate migration: V...") has
// appeared and a few seconds more have passed (so the refresh that follows an
// import is captured too); exits 2 if it never appeared. Playwright is found
// through PLAYWRIGHT_MODULE, or by the usual module resolution.
const fs = require('fs');
const { chromium } = require(process.env.PLAYWRIGHT_MODULE || 'playwright');

(async () => {
  const [url, out, maxS] = process.argv.slice(2);
  const max = Number(maxS || 120) * 1000;
  const browser = await chromium.launch({ headless: true });
  const page = await browser.newPage();
  const lines = [];
  const t0 = Date.now();
  let walkedAt = null;
  page.on('console', (m) => {
    const text = m.text().replace(/%c/g, '').replace(/ color:.*$/, '');
    lines.push(`[${((Date.now() - t0) / 1000).toFixed(1)}s] [${m.type()}] ${text}`);
    if (walkedAt === null && /delegate migration: V\d+/.test(text)) walkedAt = Date.now();
  });
  page.on('pageerror', (e) => lines.push(`[pageerror] ${e.message}`));
  await page.goto(url);
  while (Date.now() - t0 < max && (walkedAt === null || Date.now() - walkedAt < 8000)) {
    await page.waitForTimeout(500);
  }
  fs.writeFileSync(out, lines.join('\n') + '\n');
  await browser.close();
  process.exit(walkedAt === null ? 2 : 0);
})();
