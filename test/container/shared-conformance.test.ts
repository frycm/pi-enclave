import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { describe, expect, it } from "vitest";
import { ContainerBackend } from "../../src/backend/container/backend.ts";
import { createFixture } from "../conformance/fixture.ts";
import { formatRows, runConformance } from "../conformance/runner.ts";
import { SCENARIOS } from "../conformance/scenarios.ts";

const image = process.env.PI_ENCLAVE_TEST_CONTAINER_IMAGE;
const engine = process.env.PI_ENCLAVE_TEST_CONTAINER_ENGINE === "docker" ? "docker" : "podman";
describe.skipIf(!image)(`shared conformance: ${engine}`, () => {
	it("passes supported native-contract rows and explicitly refuses unsupported topology", async () => {
		const root = mkdtempSync(join(tmpdir(), "enclave-container-shared-"));
		const backend = new ContainerBackend(
			{
				kind: engine,
				fallback: engine,
				image: image ?? "",
				binary: `/usr/bin/${engine}`,
				socket: "/var/run/docker.sock",
				readableRoots: [],
			},
			root,
		);
		try {
			const unsupported = ["F10", "F13", "F14"];
			const rows = await runConformance(
				backend,
				() => {
					const fixture = createFixture();
					fixture.profile.readableRoots = [fixture.outside];
					fixture.profile.readDeny = [fixture.deniedHome, fixture.deniedFile];
					return fixture;
				},
				{
					includeFs: true,
					only: SCENARIOS.filter((scenario) => !unsupported.includes(scenario.id)).map((scenario) => scenario.id),
				},
			);
			console.info(formatRows(rows));
			expect(
				rows.filter((row) => !row.ok),
				formatRows(rows),
			).toEqual([]);
			for (const id of unsupported) {
				const fixture = createFixture();
				try {
					fixture.profile.readableRoots = [fixture.outside];
					fixture.profile.readDeny = [
						id === "F10" ? fixture.lateDenied : id === "F13" ? fixture.deniedLink : fixture.deniedUnderLink,
					];
					await expect(backend.compile(fixture.profile)).rejects.toThrow(/missing nested|unsafe nested/);
				} finally {
					fixture.cleanup();
				}
			}
		} finally {
			await backend.dispose();
			rmSync(root, { recursive: true, force: true });
		}
	}, 240_000);
});
