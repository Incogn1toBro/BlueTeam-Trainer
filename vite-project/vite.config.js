import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

// Relative base ('./') means the production build works whether served
// from a web server, a file:// URL, or a subdirectory - useful for
// air-gapped distribution where you don't know the final hosting path.
export default defineConfig({
  plugins: [react()],
  base: './',
  build: {
    outDir: 'dist',
    emptyOutDir: true,
  },
  server: {
    host: '127.0.0.1',
    port: 5173,
  },
});
