import { defineConfig } from 'vitest/config';
import pkg from './package.json';

export default defineConfig({
  // Same __TORK_SDK_VERSION__ injection as tsup.config.ts, so tests exercise
  // the same build-time-resolved version as the published dist.
  define: {
    __TORK_SDK_VERSION__: JSON.stringify(pkg.version),
  },
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts', 'src/**/*.test.ts'],
    exclude: ['node_modules', 'dist'],
  },
  esbuild: {
    target: 'es2020',
  },
});
