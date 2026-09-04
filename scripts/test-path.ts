/**
 * Remove package-runner PATH entries controlled by this checkout.
 *
 * Production deliberately refuses npm/npx's repository-local PATH injection:
 * Sandbox Runtime launches some trusted host helpers by name. The repository's
 * own verification scripts need to exercise that startup boundary, so they
 * discard only entries inside this checkout before probing or compiling SRT.
 */
import { delimiter, isAbsolute, resolve } from "node:path";

export function sanitizeVerificationPath(cwd = process.cwd()): void {
	const checkout = resolve(cwd);
	process.env.PATH = (process.env.PATH ?? "")
		.split(delimiter)
		.filter((entry) => {
			if (!isAbsolute(entry)) return false;
			const candidate = resolve(entry);
			return candidate !== checkout && !candidate.startsWith(`${checkout}/`);
		})
		.join(delimiter);
}
