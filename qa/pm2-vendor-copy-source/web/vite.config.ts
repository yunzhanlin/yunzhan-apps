import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

export default defineConfig({
  base: "./",
  plugins: [vue()],
  server: {
    port: 15173,
    strictPort: true,
    proxy: {
      "/api": {
        target: process.env.PANEL_DEV_API_TARGET || "http://127.0.0.1:19100",
        changeOrigin: true,
        configure(proxy) {
          proxy.on("proxyReq", (req) => {
            req.setHeader("origin", "http://127.0.0.1:19100");
          });
        },
      },
    },
  },
  build: {
    chunkSizeWarningLimit: 1200,
    // Emit names accepted by the existing closed local-asset verifier. Shared
    // vendor names such as runtime-core.esm-bundler must not introduce dots or
    // path components; do not widen the verifier or the byte budget instead.
    rollupOptions: {
      output: {
        chunkFileNames: (chunk) => `assets/${chunk.name.replace(/[^A-Za-z0-9_-]/g, "-")}-[hash].js`,
      },
    },
  },
});
