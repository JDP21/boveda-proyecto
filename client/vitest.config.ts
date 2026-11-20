import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    environment: "node",
<<<<<<< HEAD
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
    clearMocks: true,
    restoreMocks: true,
=======
    clearMocks: true,
    restoreMocks: true,
    include: ["src/**/*.{test,spec}.{ts,tsx}"],
>>>>>>> main
  },
});
