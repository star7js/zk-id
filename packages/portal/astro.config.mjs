import { defineConfig } from 'astro/config';

// API URL: Use Railway/Render in production, localhost in dev
const API_URL = process.env.PUBLIC_API_URL || 'http://localhost:3000';

// https://astro.build/config
export default defineConfig({
  site: 'https://star7js.github.io',
  base: process.env.NODE_ENV === 'production' ? '/zk-id' : '/',
  vite: {
    define: {
      // Make API_URL available to client-side code
      'import.meta.env.PUBLIC_API_URL': JSON.stringify(API_URL),
    },
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
