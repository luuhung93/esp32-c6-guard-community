import { defineConfig } from "vite";
import { readFileSync } from "node:fs";
const version = readFileSync(new URL("../main/config.h", import.meta.url), "utf8")
  .match(/#define GUARD_VERSION "([^"]+)"/)[1];
export default defineConfig({
  define: {"import.meta.env.VITE_GUARD_VERSION": JSON.stringify(version)},
  build: {
    cssCodeSplit: false,
    rolldownOptions: { output: {
      entryFileNames: "app.js",
      assetFileNames: asset => asset.name?.endsWith(".css") ? "styles.css" : "[name][extname]",
    } },
  },
});
