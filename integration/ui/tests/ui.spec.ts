import { test, expect, Page } from '@playwright/test';
import * as fs from 'fs';
import * as path from 'path';
import * as crypto from 'crypto';

const WORK = path.join(__dirname, '..', '.work');
const API_KEY = 'e2e-key';
const LISTENER_PORT = '5099';

// Give the UI its API key (persisted in localStorage) and land on a fresh dashboard.
async function open(page: Page) {
  await page.goto('/');
  await expect(page.locator('#title')).toHaveText('Dashboard');
  await page.locator('#apiKey').fill(API_KEY);
  await page.locator('#apiKey').blur();
  await expect(page.locator('.toast')).toContainText('API key saved');
}

async function tab(page: Page, name: string) {
  await page.locator(`#nav button[data-tab="${name}"]`).click();
}

test('the node UI drives a full configuration and a loopback transfer', async ({ page }) => {
  await open(page);

  // health reported online
  await expect(page.locator('#healthTxt')).toHaveText('Node online');

  // 1. partner
  await tab(page, 'partners');
  await page.locator('input[name="id"]').fill('SELF');
  await page.getByRole('button', { name: 'Create partner' }).click();
  await expect(page.locator('td.mono', { hasText: /^SELF$/ })).toBeVisible();

  // 2. virtual file (RECEIVE, binary variable)
  await tab(page, 'files');
  await page.locator('input[name="id"]').fill('IN');
  await page.locator('select[name="direction"]').selectOption('RECEIVE');
  await page.locator('input[name="receiveDirectory"]').fill(path.join(WORK, 'received'));
  await page.getByRole('button', { name: 'Create virtual file' }).click();
  await expect(page.locator('td.mono', { hasText: /^IN$/ })).toBeVisible();

  // 3. listener, auto-started, must reach RUNNING
  await tab(page, 'listeners');
  await page.locator('input[name="serverId"]').fill('SELF');
  await page.locator('input[name="port"]').fill(LISTENER_PORT);
  await page.locator('input[name="receiveDirectory"]').fill(path.join(WORK, 'received'));
  await page.locator('input[name="sendDirectory"]').fill(path.join(WORK, 'send'));
  await page.getByRole('button', { name: 'Create listener' }).click();
  await expect(page.locator('tr', { hasText: 'SELF' }).locator('.pill.ok', { hasText: 'RUNNING' })).toBeVisible({ timeout: 20_000 });

  // 4. remote server pointing back at our own listener (loopback)
  await tab(page, 'remotes');
  await page.locator('input[name="name"]').fill('self');
  await page.locator('input[name="host"]').fill('127.0.0.1');
  await page.locator('input[name="port"]').fill(LISTENER_PORT);
  await page.locator('input[name="serverId"]').fill('SELF');
  await page.locator('input[name="defaultServer"]').check();
  await page.getByRole('button', { name: 'Create remote server' }).click();
  await expect(page.locator('td.mono', { hasText: /^self$/ })).toBeVisible();

  // connectivity test succeeds
  await page.locator('tr', { hasText: 'self' }).getByRole('button', { name: 'Test' }).click();
  await expect(page.locator('.toast', { hasText: 'Reachable' })).toBeVisible({ timeout: 15_000 });

  // 5. send a real file through the UI, expect it to reach COMPLETED
  const src = path.join(WORK, 'send', 'hello.dat');
  const payload = crypto.randomBytes(256 * 1024);
  fs.writeFileSync(src, payload);

  await tab(page, 'send');
  await page.locator('select[name="server"]').selectOption('self');
  await page.locator('input[name="partnerId"]').fill('SELF');
  await page.locator('input[name="filename"]').fill(src);
  await page.locator('input[name="remoteFilename"]').fill('IN');
  await page.getByRole('button', { name: 'Start transfer' }).click();
  await expect(page.locator('.toast', { hasText: 'Transfer queued' })).toBeVisible();

  // the outbound table shows it completing
  await expect(page.locator('#outBody tr').first().locator('.pill', { hasText: 'COMPLETED' })).toBeVisible({ timeout: 30_000 });

  // the file physically landed on the receive side with the same content
  await expect
    .poll(() => {
      const dir = path.join(WORK, 'received');
      const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
      const match = files.find((f) => {
        const buf = fs.readFileSync(path.join(dir, f));
        return buf.length === payload.length && crypto.timingSafeEqual(buf, payload);
      });
      return match ? true : false;
    }, { timeout: 30_000 })
    .toBe(true);

  // 6. both inbound and outbound records are listed
  await tab(page, 'transfers');
  await page.getByRole('button', { name: 'Outbound' }).click();
  await expect(page.locator('tbody tr').first()).toContainText('COMPLETED');
  await page.getByRole('button', { name: 'Inbound' }).click();
  await expect(page.locator('tbody tr').first()).toContainText('IN');
});

test('the admin API rejects requests without the API key', async ({ page }) => {
  // fresh context without the key set
  const res = await page.request.get('/api/v1/config/partners');
  expect(res.status()).toBe(401);
});
