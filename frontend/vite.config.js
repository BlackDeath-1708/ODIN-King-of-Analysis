import react from '@vitejs/plugin-react'
import { defineConfig } from 'vite'

// Backend base URL for the dev proxy. The backend isn't part of this
// frontend project; override with VITE_BACKEND_URL if it isn't running on
// the documented default port. Always localhost — the proxy runs on the
// same host machine as the backend, so this works regardless of which LAN
// IP that machine has.
const backendTarget = process.env.VITE_BACKEND_URL || 'http://localhost:5000'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    // Listen on all network interfaces (0.0.0.0) so the dashboard is
    // reachable from other devices on the same LAN via this machine's IP.
    host: true,
    proxy: {
      // Forwards /api/* to the backend unchanged — same path, same
      // payloads, just resolved server-side so relative fetch()/EventSource
      // calls in the frontend keep working from any device on the LAN.
      '/api': {
        target: backendTarget,
        changeOrigin: true,
      },
    },
  },
})
