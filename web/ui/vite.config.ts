import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";
import tailwindcss from "@tailwindcss/vite";

// The Go server embeds ../internal/server/dist via go:embed, so the production
// build must land there. The dev server proxies /api to the Go backend on 6151.
export default defineConfig({
  plugins: [react(), tailwindcss()],
  base: "/",
  build: {
    outDir: "../internal/server/dist",
    emptyOutDir: true,
  },
  server: {
    proxy: {
      "/api": "http://localhost:6151",
    },
  },
});
