import { ContainerBackend, type ContainerBackendOptions } from "./container.ts";

export type DockerBackendOptions = Omit<ContainerBackendOptions, "engine" | "machine">;

/** Experimental local Linux Docker daemon adapter. */
export class DockerBackend extends ContainerBackend {
	constructor(options: DockerBackendOptions) {
		super({ ...options, engine: "docker" });
	}
}
