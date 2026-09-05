import type { ExtensionAPI } from "@earendil-works/pi-coding-agent";
import type { ActionLock } from "../gate/lock.ts";

type OwnedTool = Parameters<ExtensionAPI["registerTool"]>[0];

/** The tool's complete invocation owns its operations until execute settles. */
export function bindOwnedTool(tool: OwnedTool, lock: ActionLock, bypass: () => boolean = () => false): OwnedTool {
	return {
		...tool,
		execute: (id, input, signal, onUpdate, ctx) => {
			const run = () => tool.execute(id, input, signal, onUpdate, ctx);
			return bypass() ? run() : lock.runInvocation(id, tool.name, input, ctx.cwd, run, signal);
		},
	};
}
