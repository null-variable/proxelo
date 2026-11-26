import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { defineConfig, type Plugin } from "vite";
import react from "@vitejs/plugin-react";

// The build lands in internal/ui/dist, which the Go binary embeds. `bun run
// dev` proxies the API to a local control plane (PROXELO_API, default
// 127.0.0.1:9443).
// emptyOutDir clears dist/, including the .gitkeep that lets go build embed
// it before the first web build; keepGitkeep puts it back.
function keepGitkeep(): Plugin {
  return {
    name: "proxelo-keep-gitkeep",
    closeBundle() {
      writeFileSync(fileURLToPath(new URL("../internal/ui/dist/.gitkeep", import.meta.url)), "");
    },
  };
}

export default defineConfig({
  plugins: [react(), keepGitkeep()],
  build: {
    outDir: "../internal/ui/dist",
    emptyOutDir: true,
    assetsInlineLimit: 0,
  },
  server: {
    proxy: { "/api": `http://${process.env.PROXELO_API ?? "127.0.0.1:9443"}` },
  },
});
