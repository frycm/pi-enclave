import { ContainerBackend, type ContainerBackendOptions } from "./container.ts";

export type PodmanBackendOptions = Omit<ContainerBackendOptions, "engine" | "socket">;

/** Experimental rootless Linux / named macOS Podman machine adapter. */
export class PodmanBackend extends ContainerBackend {
	constructor(options: PodmanBackendOptions) {
		super({ ...options, engine: "podman" });
	}
}
