import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ContainerBackend } from "../../src/backend/container/backend.ts";
import { qualifyContainer, requireContainerQualification } from "../../src/backend/container/qualification.ts";
import type { BackendSettings } from "../../src/config/types.ts";
import { exerciseProduction } from "./production-integration.ts";

const image = process.env.PI_ENCLAVE_TEST_CONTAINER_IMAGE;
const engine = process.env.PI_ENCLAVE_TEST_CONTAINER_ENGINE === "docker" ? "docker" : "podman";
describe.skipIf(!image)(`real ${engine} qualification`, () => {
	it("passes the complete local contract and reuses only an exact protected record", async () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-container-test-"));
		const settings: BackendSettings = {
			kind: engine,
			fallback: engine,
			image: image ?? "",
			binary: `/usr/bin/${engine}`,
			socket: "/var/run/docker.sock",
			readableRoots: [],
		};
		const backend = new ContainerBackend(settings, join(root, "control"));
		try {
			const record = await qualifyContainer(backend, join(root, "qualified"));
			for (const row of record.rows) console.info(`PASS ${engine} ${row.name} (${Math.round(row.ms)} ms)`);
			expect(record.rows).toHaveLength(14);
			const fresh = new ContainerBackend(settings, join(root, "control"));
			try {
				expect((await requireContainerQualification(fresh, join(root, "qualified"))).identity).toBe(record.identity);
			} finally {
				await fresh.dispose();
			}
			await exerciseProduction(settings, root);
		} finally {
			await backend.dispose();
			rmSync(root, { recursive: true, force: true });
		}
	}, 180_000);
});
