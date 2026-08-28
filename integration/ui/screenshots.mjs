import { chromium } from '@playwright/test';
const base = process.env.BASE || 'http://127.0.0.1:8194';
const key = process.env.KEY || 'k';
const out = process.env.OUT || './shots';
const theme = process.env.THEME || 'dark';
const browser = await chromium.launch();
const ctx = await browser.newContext({ viewport: { width: 1320, height: 900 }, deviceScaleFactor: 2 });
await ctx.addInitScript(([k, t]) => { localStorage.setItem('pw-apikey', k); localStorage.setItem('pw-theme', t); }, [key, theme]);
const page = await ctx.newPage();
await page.goto(base);
await page.waitForTimeout(600);
for (const t of ['dashboard', 'listeners', 'partners', 'certs', 'send', 'transfers']) {
  await page.locator(`#nav button[data-tab="${t}"]`).click();
  await page.waitForTimeout(800);
  await page.screenshot({ path: `${out}/${t}.png`, fullPage: true });
  console.log('shot', t);
}
await browser.close();
