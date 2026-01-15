import { defineConfig } from 'tsup';

export default defineConfig({
  entry: {
    index: 'src/index.ts',
    client: 'src/client.ts',
  },
  format: ['esm', 'cjs'],
  // Skip tsup's DTS bundling - use tsc directly via build script
  dts: false,
  skipNodeModulesBundle: true,
  splitting: false,
  sourcemap: true,
  clean: true,
});
