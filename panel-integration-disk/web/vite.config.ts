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
  build: { chunkSizeWarningLimit: 1200 },
});
