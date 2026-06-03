import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/e2e',
  use: {
    baseURL: 'http://localhost:3000',
  },
  webServer: {
    command: 'C:\\Users\\Gonzalo\\.bun\\bin\\bun.exe run src/index.ts',
    url: 'http://localhost:3000',
    reuseExistingServer: true,
  },
});
