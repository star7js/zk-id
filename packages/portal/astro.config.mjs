import { defineConfig } from 'astro/config';

// https://astro.build/config
export default defineConfig({
  site: 'https://star7js.github.io',
  base: process.env.NODE_ENV === 'production' ? '/zk-id' : '/',
  vite: {
    server: {
      proxy: {
        // Proxy API requests to demo server during development
        '/api': {
          target: 'http://localhost:3000',
          changeOrigin: true,
        },
        // Proxy circuit files to demo server
        '/circuits': {
          target: 'http://localhost:3000',
          changeOrigin: true,
        },
      },
    },
  },
});
