import { defineConfig } from 'astro/config';

// API URL for development proxy
const API_URL = process.env.PUBLIC_API_URL || 'http://localhost:3000';

// https://astro.build/config
export default defineConfig({
  site: 'https://zk-id.io',
  base: '/',
  vite: {
    server: {
      proxy: {
        // Proxy API requests to demo server during development
        '/api': {
          target: API_URL,
          changeOrigin: true,
        },
        // Proxy circuit files to demo server
        '/circuits': {
          target: API_URL,
          changeOrigin: true,
        },
      },
    },
  },
});
