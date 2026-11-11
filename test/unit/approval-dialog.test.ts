import type { KeybindingsManager as AppKeybindings, ExtensionUIContext, Theme } from "@earendil-works/pi-coding-agent";
import { type KeybindingsConfig, KeybindingsManager, type TUI, TUI_KEYBINDINGS } from "@earendil-works/pi-tui";
import { describe, expect, it, vi } from "vitest";
import { type ConfirmUI, createConfirmEscalator, type EscalationEvent } from "../../src/escalate/confirm.ts";
import { ApprovalDialog } from "../../src/escalate/dialog.ts";
import { canonicalize } from "../../src/policy/canonical.ts";

const DOWN = "\x1b[B";
const PAGE_DOWN = "\x1b[6~";
const ENTER = "\r";

const keys = (config?: KeybindingsConfig) => new KeybindingsManager(TUI_KEYBINDINGS, config);

function dialog(message: string, keybindings = keys()) {
	const done = vi.fn<(answer: boolean) => void>();
	const controller = new AbortController();
	let rows = 12;
	const component = new ApprovalDialog(
		"Approve?",
		message,
		keybindings,
		() => rows,
		() => {},
		done,
		controller.signal,
	);
	return {
		component,
		done,
		controller,
		resize: (value: number) => {
			rows = value;
		},
	};
}

describe("permission approval dialog", () => {
	it("defaults to denial and uses the person's configured confirmation binding", () => {
		const { component, done } = dialog("short", keys({ "tui.select.confirm": "ctrl+y" }));
		component.render(80);
		component.handleInput(ENTER);
		expect(done).not.toHaveBeenCalled();
		component.handleInput("\x19");
		expect(done).toHaveBeenCalledExactlyOnceWith(false);
	});

	it("shows every page before permitting approval, even with queued navigation input", () => {
		const lines = Array.from({ length: 40 }, (_, index) => `CANONICAL_${index}`);
		const { component, done } = dialog(lines.join("\n"));
		const seen = new Set<string>();
		const render = () => {
			for (const line of component.render(80)) seen.add(line);
		};
		render();
		component.handleInput(DOWN);
		component.handleInput(ENTER);
		expect(done).not.toHaveBeenCalled();
		for (let i = 0; i < 20; i++) component.handleInput(PAGE_DOWN);
		render();
		component.handleInput(ENTER);
		expect(done).not.toHaveBeenCalled();
		for (let i = 0; i < 10; i++) {
			component.handleInput(PAGE_DOWN);
			render();
		}
		for (const line of lines) expect(seen.has(line), line).toBe(true);
		component.handleInput(ENTER);
		expect(done).toHaveBeenCalledExactlyOnceWith(true);
	});

	it("requires a usable viewport and resets review after reflow", () => {
		const { component, done, resize } = dialog("word ".repeat(200));
		resize(9);
		expect(component.render(80)).toEqual(["Resize terminal to review; cancel to deny."]);
		component.handleInput(DOWN);
		component.handleInput(ENTER);
		expect(done).not.toHaveBeenCalled();
		resize(24);
		component.render(120);
		component.handleInput(DOWN);
		component.render(40);
		component.handleInput(ENTER);
		expect(done).toHaveBeenCalledExactlyOnceWith(false);
	});

	it.each(["abort", "dispose", "cancel"] as const)("denies exactly once on %s", (method) => {
		const { component, done, controller } = dialog("short");
		component.render(80);
		component.handleInput(DOWN);
		if (method === "abort") controller.abort();
		if (method === "dispose") component.dispose();
		if (method === "cancel") component.handleInput("\x1b");
		component.handleInput(ENTER);
		component.dispose();
		expect(done).toHaveBeenCalledExactlyOnceWith(false);
	});
});

describe("permission dialog integration", () => {
	const action = canonicalize({
		tool: "bash",
		input: { command: "echo safe\nrm -rf /work" },
		cwd: "/work",
		home: "/home/u",
		profileName: "dev",
	});
	function setup(mode: "tui" | "rpc", timeoutMs = 1_000, interact = true) {
		const blocked: unknown[] = [];
		const viewports: unknown[] = [];
		const rendered: string[] = [];
		const events: EscalationEvent[] = [];
		const pending = vi.fn();
		const custom: ExtensionUIContext["custom"] = async <T>(
			factory: Parameters<ExtensionUIContext["custom"]>[0],
			options: Parameters<ExtensionUIContext["custom"]>[1],
		) => {
			blocked.push(options?.blocked);
			viewports.push({ overlay: options?.overlay, ...options?.overlayOptions });
			return new Promise<T>((resolve) => {
				const tui = { terminal: { rows: 24 }, requestRender: () => {} } as unknown as TUI;
				const component = factory(tui, {} as Theme, keys() as AppKeybindings, (result) => resolve(result as T));
				if (component instanceof Promise) throw new Error("unexpected asynchronous factory");
				rendered.push(...component.render(160));
				if (interact) {
					component.handleInput?.(DOWN);
					component.handleInput?.(ENTER);
				}
			});
		};
		const ui: ConfirmUI = { custom, confirm: vi.fn(async () => true) };
		const escalator = createConfirmEscalator({
			ui: () => ui,
			attendance: () => ({ configured: mode, effective: mode }),
			confirmTimeoutMs: () => timeoutMs,
			onEscalation: (event) => events.push(event),
			onUnattended: pending,
		});
		return { escalator, blocked, viewports, rendered, events, pending, ui };
	}
	it("reports permission-blocked status while reviewing the canonical action", async () => {
		const { escalator, blocked, viewports, rendered, ui, pending } = setup("tui");
		expect(await escalator.confirm(action, "ask rule")).toBe(true);
		expect(blocked).toEqual([{ kind: "permission", message: "Review a pi-enclave action" }]);
		expect(viewports).toEqual([{ overlay: true, width: "100%", maxHeight: "100%", margin: 0 }]);
		expect(rendered.join("\n")).toContain("echo safe\\nrm -rf /work");
		expect(ui.confirm).not.toHaveBeenCalled();
		expect(pending).not.toHaveBeenCalled();
	});
	it("retains the authenticated RPC confirmation path", async () => {
		const { escalator, blocked, ui } = setup("rpc");
		expect(await escalator.confirm(action, "ask rule")).toBe(true);
		expect(blocked).toEqual([]);
		expect(ui.confirm).toHaveBeenCalledOnce();
	});
	it("closes on timeout and writes the existing pending record", async () => {
		const { escalator, events, pending } = setup("tui", 10, false);
		expect(await escalator.confirm(action, "ask rule")).toBe(false);
		expect(events[0]?.outcome).toBe("timeout");
		expect(pending).toHaveBeenCalledOnce();
	});
	it("rejects an affirmative RPC reply that arrives after the deadline", async () => {
		const { escalator, ui, events } = setup("rpc", 1);
		ui.confirm = () => new Promise((resolve) => setTimeout(() => resolve(true), 15));
		expect(await escalator.confirm(action, "ask rule")).toBe(false);
		expect(events[0]?.outcome).toBe("timeout");
	});
});
