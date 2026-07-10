import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 5173,
    // 开发时把 /api 代理到后端 Express（3000）
    proxy: {
      "/api": "http://localhost:3000",
    },
  },
  build: {
    outDir: "dist",
    // 相对路径，便于 Express 静态托管
    base: "./",
  },
});
