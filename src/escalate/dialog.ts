/** A permission-blocked TUI dialog; only a complete, explicit review can approve. */
import type { ExtensionUIContext, KeybindingsManager } from "@earendil-works/pi-coding-agent";
import { truncateToWidth, wrapTextWithAnsi } from "@earendil-works/pi-tui";

export class ApprovalDialog {
	readonly capturesViewportInput = true;
	private lines: string[] = [];
	private width = 0;
	private pageSize = 0;
	private top = 0;
	private viewedThrough = 0;
	private approve = false;
	private settled = false;

	constructor(
		private readonly title: string,
		private readonly message: string,
		private readonly keybindings: Pick<KeybindingsManager, "matches" | "getKeys">,
		private readonly rows: () => number,
		private readonly requestRender: () => void,
		private readonly done: (answer: boolean) => void,
		private readonly signal: AbortSignal,
	) {
		signal.addEventListener("abort", this.abort, { once: true });
		if (signal.aborted) this.finish(false);
	}

	private readonly abort = () => this.finish(false);

	private finish(answer: boolean): void {
		if (this.settled) return;
		this.settled = true;
		this.signal.removeEventListener("abort", this.abort);
		this.done(answer && !this.signal.aborted);
	}

	dispose(): void {
		this.finish(false);
	}

	invalidate(): void {
		// Theme changes do not change plain-text content or the review position.
	}

	render(width: number): string[] {
		const pageSize = Math.min(18, Math.max(1, this.rows() - 6));
		if (width !== this.width || pageSize !== this.pageSize) {
			this.lines = wrapTextWithAnsi(this.message, Math.max(1, width));
			this.width = width;
			this.pageSize = pageSize;
			this.top = 0;
			this.viewedThrough = 0;
			this.approve = false;
		}
		if (!this.canDisplay()) return [truncateToWidth("Resize terminal to review; cancel to deny.", width)];
		const body = this.lines.slice(this.top, this.top + this.pageSize);
		this.viewedThrough = Math.max(this.viewedThrough, this.top + body.length);
		const keys = (name: Parameters<KeybindingsManager["getKeys"]>[0]) => this.keybindings.getKeys(name).join("/");
		return [
			truncateToWidth(this.title, width),
			"",
			...body,
			truncateToWidth(`Lines ${this.top + 1}-${this.top + body.length} of ${this.lines.length}`, width),
			`${this.approve ? "  " : "> "}Deny`,
			`${this.approve ? "> " : "  "}Approve once${this.reviewed() ? "" : " (read all pages first)"}`,
			truncateToWidth(
				`${keys("tui.select.pageUp")}/${keys("tui.select.pageDown")} pages | ${keys("tui.select.up")}/${keys("tui.select.down")} choose | ${keys("tui.select.confirm")} confirm | ${keys("tui.select.cancel")} deny`,
				width,
			),
		];
	}

	private canDisplay(): boolean {
		return this.width >= 30 && this.rows() >= 10;
	}

	private reviewed(): boolean {
		return this.canDisplay() && this.viewedThrough >= this.lines.length && this.lines.length > 0;
	}

	handleInput(data: string): void {
		if (this.settled) return;
		const matches = (name: Parameters<KeybindingsManager["matches"]>[1]) => this.keybindings.matches(data, name);
		if (matches("tui.select.cancel")) {
			this.finish(false);
			return;
		}
		if (matches("tui.select.confirm")) {
			if (!this.approve) this.finish(false);
			else if (this.reviewed()) this.finish(true);
			return;
		}
		if (matches("tui.select.up")) this.approve = false;
		else if (matches("tui.select.down")) this.approve = true;
		else if (matches("tui.select.pageDown")) {
			// Never skip content even when inputs arrive faster than rendering.
			this.top = Math.min(this.top + this.pageSize, this.viewedThrough, Math.max(0, this.lines.length - 1));
		} else if (matches("tui.select.pageUp")) this.top = Math.max(0, this.top - this.pageSize);
		this.requestRender();
	}
}

export function confirmPermission(
	ui: Pick<ExtensionUIContext, "custom">,
	title: string,
	message: string,
	signal: AbortSignal,
): Promise<boolean> {
	if (signal.aborted) return Promise.resolve(false);
	return ui.custom<boolean>(
		(tui, _theme, keybindings, done) =>
			new ApprovalDialog(
				title,
				message,
				keybindings,
				() => tui.terminal.rows,
				() => tui.requestRender(),
				done,
				signal,
			),
		{
			// Own the viewport so transcript widgets/footer cannot clip reviewed lines.
			overlay: true,
			overlayOptions: { width: "100%", maxHeight: "100%", margin: 0 },
			blocked: { kind: "permission", message: "Review a pi-enclave action" },
		},
	);
}
