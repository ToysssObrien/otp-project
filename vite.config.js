import { resolve } from "node:path";
import { defineConfig } from "vite";

export default defineConfig({
  root: "frontend",
  publicDir: "public",
  build: {
    outDir: "../static",
    emptyOutDir: false,
    rollupOptions: {
      input: {
        ops: resolve(__dirname, "frontend/ops.html"),
        otp: resolve(__dirname, "frontend/otp.html")
      }
    }
  }
});
