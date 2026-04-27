import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig({
  plugins: [react()],
  server: {
    port: 7517,
    proxy: {
      "/oauth": "http://localhost:7300",
      "/graphql": "http://localhost:7300",
      "/api": "http://localhost:7300",
      "/.well-known": "http://localhost:7300",
    },
  },
});
