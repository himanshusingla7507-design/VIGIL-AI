import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import tailwindcss from '@tailwindcss/vite'

export default defineConfig({
  plugins: [react(), tailwindcss()],
  server: {
    port: 5173,
    proxy: {
      '/scan': 'http://127.0.0.1:5000',
      '/history': 'http://127.0.0.1:5000',
      '/model-info': 'http://127.0.0.1:5000',
      '/health': 'http://127.0.0.1:5000',
      '/threat-feed': 'http://127.0.0.1:5000',
      '/scam-cases': 'http://127.0.0.1:5000',
      '/legal-knowledge': 'http://127.0.0.1:5000',
    },
  },
  test: {
    environment: 'jsdom',
    setupFiles: './src/test-setup.ts',
  },
})
