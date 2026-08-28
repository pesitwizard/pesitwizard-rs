import { defineConfig, devices } from '@playwright/test';

const ADMIN_PORT = process.env.PW_ADMIN_PORT || '8199';

// The web UI is served by the node's admin API port.
export default defineConfig({
  testDir: './tests',
  fullyParallel: false,
  workers: 1,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 15_000 },
  reporter: process.env.CI ? [['github'], ['list']] : [['list']],
  use: {
    baseURL: `http://127.0.0.1:${ADMIN_PORT}`,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'bash run-node.sh',
    url: `http://127.0.0.1:${ADMIN_PORT}/actuator/health`,
    reuseExistingServer: false,
    timeout: 60_000,
    stdout: 'pipe',
    stderr: 'pipe',
  },
});
