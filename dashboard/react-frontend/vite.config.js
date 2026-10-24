import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Backend contract remains unchanged. These are development-only proxies.
// The real guard (python3 -m guard.api) listens on 8000. For the stand-in,
// run with ACCRUE_API=http://127.0.0.1:8001.
const target = process.env.ACCRUE_API || 'http://127.0.0.1:8000';

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    strictPort: true,
    proxy: Object.fromEntries(
      ['/whoami', '/events', '/stream', '/override', '/verify', '/limits', '/replay', '/demo'].map((path) => [path, target]),
    ),
  },
});
