/**
 * SDK version, injected at build time from package.json (tsup's `define`
 * for the published dist, vitest's `define` for tests) so it can never
 * drift from the shipped package.json the way a hand-typed literal would.
 */
declare const __TORK_SDK_VERSION__: string | undefined;

export const SDK_VERSION: string =
  typeof __TORK_SDK_VERSION__ !== 'undefined' ? __TORK_SDK_VERSION__ : '0.0.0-dev';
