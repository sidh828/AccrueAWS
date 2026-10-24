import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Backend contract remains unchanged. These are development-only proxies.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: {
      '/events': 'http://127.0.0.1:8001',
      '/stream': 'http://127.0.0.1:8001',
      '/override': 'http://127.0.0.1:8001',
      '/verify': 'http://127.0.0.1:8001',
      '/demo': 'http://127.0.0.1:8001',
    },
  },
});
