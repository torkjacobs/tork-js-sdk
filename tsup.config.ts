import { defineConfig } from 'tsup';
import pkg from './package.json';

// The User-Agent and x-tork-sdk-version headers sent by attestation-report.ts
// must read the real published version, not a hand-typed literal that can go
// stale (see @torknetwork/sdk, which reports "1.0.0" while its package.json
// says "2.0.0"). Injecting it here means it is impossible for dist to ship a
// version string that disagrees with package.json.
export default defineConfig({
  entry: ['src/index.ts'],
  format: ['cjs', 'esm'],
  dts: true,
  clean: true,
  define: {
    __TORK_SDK_VERSION__: JSON.stringify(pkg.version),
  },
});
