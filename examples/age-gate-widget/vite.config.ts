import { defineConfig } from 'vite';

export default defineConfig({
  server: {
    port: 5173,
    open: true,
  },
  build: {
    lib: {
      entry: 'src/age-gate.ts',
      name: 'ZkIdAgeGateWidget',
      fileName: (format) => `age-gate.${format}.js`,
      formats: ['es', 'umd'],
    },
    rollupOptions: {
      external: ['@zk-id/core', '@zk-id/sdk'],
      output: {
        globals: {
          '@zk-id/core': 'ZkIdCore',
          '@zk-id/sdk': 'ZkIdSdk',
        },
      },
    },
  },
  optimizeDeps: {
    exclude: ['@zk-id/core', '@zk-id/sdk'],
  },
});
