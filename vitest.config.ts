import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['src/**/*.test.ts'],
    testTimeout: 10000,
    hookTimeout: 10000,
    // Test groups via CLI: npm run test:atomic, test:integration, test:baseline
  },
});
