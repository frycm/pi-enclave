import { defineConfig } from "vitest/config";

export default defineConfig({
	test: {
		include: ["test/**/*.test.ts"],
		// Conformance tests spawn real sandboxed processes; give them room.
		testTimeout: 30_000,
		hookTimeout: 30_000,
	},
});
