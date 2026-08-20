import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// En développement, le front tourne sur 5173 et le backend sur 7998. Le
// mandataire évite d'avoir à ouvrir CORS côté Spring : en production les deux
// sont servis par la même origine, et CORS ne devrait donc jamais être requis.
export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    proxy: {
      '/api': { target: 'http://127.0.0.1:7998', changeOrigin: true },
    },
  },
  build: {
    // Le backend sert ces fichiers depuis son classpath : une seule origine,
    // un seul port, rien à configurer pour l'utilisateur.
    outDir: '../backend/src/main/resources/static',
    emptyOutDir: true,
  },
})
