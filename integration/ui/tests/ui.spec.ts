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

test('certificates: generate a local CA and issue a stored certificate', async ({ page }) => {
  await open(page);
  await tab(page, 'certs');

  const caPanel = page.locator('.panel', { hasText: 'Local certificate authority' });
  const genBtn = caPanel.getByRole('button', { name: 'Generate local CA' });
  if (await genBtn.count()) {
    await caPanel.locator('input[name="commonName"]').fill('PeSIT Wizard E2E CA');
    await genBtn.click();
    await expect(page.locator('.toast', { hasText: 'Local CA generated' })).toBeVisible();
  }
  await expect(caPanel.locator('td.mono', { hasText: 'PeSIT Wizard E2E CA' })).toBeVisible();

  // issue a certificate from the local CA and store it as a keystore
  const issue = page.locator('.panel', { hasText: 'Issue certificate' });
  await issue.locator('input[name="commonName"]').fill('leaf.e2e.test');
  await issue.locator('input[name="_sans"]').fill('DNS:leaf.e2e.test,IP:127.0.0.1');
  await issue.locator('input[name="storeAs"]').fill('issued-leaf');
  await issue.getByRole('button', { name: 'Issue' }).click();
  await expect(page.locator('.toast', { hasText: 'Certificate issued' })).toBeVisible();

  // it now appears as a keystore, valid, with the right subject
  const ksPanel = page.locator('.panel', { hasText: 'Keystores' });
  const row = ksPanel.locator('tr', { hasText: 'issued-leaf' });
  await expect(row.locator('td.mono', { hasText: 'issued-leaf' })).toBeVisible();
  await expect(row.locator('.pill.ok', { hasText: 'valid' })).toBeVisible();
  await expect(row).toContainText('leaf.e2e.test');
});

test('system: audit records actions and a backup restores deleted configuration', async ({ page }) => {
  page.on('dialog', (d) => d.accept());
  await open(page);

  // create a partner so there is something to audit and back up
  await tab(page, 'partners');
  await page.locator('input[name="id"]').fill('BACKUP_TEST');
  await page.getByRole('button', { name: 'Create partner' }).click();
  await expect(page.locator('td.mono', { hasText: /^BACKUP_TEST$/ })).toBeVisible();

  // the audit log shows the config action
  await tab(page, 'system');
  await expect(page.locator('#auditBody')).toContainText('BACKUP_TEST');
  await expect(page.locator('#auditBody tr', { hasText: 'config' }).first()).toBeVisible();

  // download a backup and confirm it carries the partner
  const [dl] = await Promise.all([page.waitForEvent('download'), page.getByRole('button', { name: 'Download backup' }).click()]);
  const backupPath = await dl.path();
  const bundle = JSON.parse(fs.readFileSync(backupPath, 'utf8'));
  expect(JSON.stringify(bundle.tables.partners)).toContain('BACKUP_TEST');

  // delete the partner
  await tab(page, 'partners');
  await page.locator('tr', { hasText: 'BACKUP_TEST' }).getByRole('button', { name: '✕' }).click();
  await expect(page.locator('td.mono', { hasText: /^BACKUP_TEST$/ })).toHaveCount(0);

  // restore from the downloaded file — the partner comes back
  await tab(page, 'system');
  const [chooser] = await Promise.all([page.waitForEvent('filechooser'), page.getByRole('button', { name: 'Restore from file…' }).click()]);
  await chooser.setFiles(backupPath);
  await expect(page.locator('.toast', { hasText: 'Restore complete' })).toBeVisible();
  await tab(page, 'partners');
  await expect(page.locator('td.mono', { hasText: /^BACKUP_TEST$/ })).toBeVisible();
});
