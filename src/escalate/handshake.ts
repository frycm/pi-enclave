/**
 * The RPC attendance handshake.
 *
 * pi 0.84.2 gives an extension exactly four fixed UI request methods -- select,
 * confirm, input, and fire-and-forget -- and nothing custom. So this is not a
 * new message type; it is a defined *use* of `ctx.ui.input`, which is the only
 * one that can carry a value back.
 *
 * The trust model is possession of a shared secret: the operator provisions it
 * once on the machine running pi and copies it to the client through whatever
 * channel they already trust. It is an HMAC and not PKI because the client and
 * pi run under the same operator and there is no third party to certify.
 *
 * What it binds is the **channel**, not each confirm. Binding each approval
 * would need a per-request nonce inside `confirm`'s boolean response, which the
 * baseline cannot carry -- that is item 4 in the core changes to propose to pi.
 * Until then, a verified client is one pi-enclave will show dialogs to, and
 * whoever holds the secret is the console.
 *
 * A client that knows nothing about this sees an `input` prompt it cannot
 * answer, times out, and the session runs unattended. That is the safe outcome
 * and it is the *expected* one today, since no client implements it yet.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { checkSecureFile } from "../state/dir.ts";

/** Ten seconds. Long enough for a client that knows the protocol, short enough not to stall a run. */
export const HANDSHAKE_TIMEOUT_MS = 10_000;

export const SECRET_BYTES = 32;
export const NONCE_BYTES = 16;

/** The UI surface the handshake needs. Narrow so it can be faked exactly. */
export interface HandshakeUI {
	input(title: string, placeholder?: string, options?: { timeout?: number }): Promise<string | undefined>;
}

export interface HandshakeOptions {
	ui: HandshakeUI;
	sessionId: string;
	secretPath: string;
	/** Injected by tests. */
	nonce?: string;
	readSecret?: (path: string) => string | undefined;
	checkFile?: (path: string) => string | undefined;
}

export type HandshakeResult =
	| { verified: true }
	| { verified: false; reason: "no-secret" | "insecure-secret" | "timeout" | "cancelled" | "bad-mac" };

/** `base64(HMAC-SHA256(secret, nonce || sessionId))`. */
export function expectedProof(secret: Buffer, nonce: string, sessionId: string): string {
	return createHmac("sha256", secret).update(nonce).update(sessionId).digest("base64");
}

/**
 * Run the handshake once.
 *
 * Once, deliberately: a retry loop would let a client brute-force the proof,
 * and there is nothing a second attempt tells us that the first did not.
 */
export async function runHandshake(options: HandshakeOptions): Promise<HandshakeResult> {
	const check = options.checkFile ?? ((path: string) => checkSecureFile(path));
	const problem = check(options.secretPath);
	if (problem) {
		// "Missing" and "world-readable" are different diagnoses and the operator
		// needs to be able to tell them apart.
		return { verified: false, reason: problem.includes("does not exist") ? "no-secret" : "insecure-secret" };
	}

	const read = options.readSecret ?? ((path: string) => readFileSync(path, "utf8"));
	let secret: Buffer;
	try {
		const raw = read(options.secretPath);
		if (!raw) return { verified: false, reason: "no-secret" };
		secret = Buffer.from(raw.trim(), "base64");
	} catch {
		return { verified: false, reason: "no-secret" };
	}
	if (secret.length < SECRET_BYTES) return { verified: false, reason: "insecure-secret" };

	const nonce = options.nonce ?? randomBytes(NONCE_BYTES).toString("hex");

	// The nonce goes in the title as well as the placeholder: a client reading
	// either field finds it, and a person who sees this dialog by accident gets
	// something they can recognise rather than a bare prompt.
	const answer = await options.ui.input(`pi-enclave attendance ${nonce}`, nonce, { timeout: HANDSHAKE_TIMEOUT_MS });

	// pi resolves a timeout and a cancel to the same `undefined`, so they cannot
	// be told apart here. Both mean the same thing.
	if (answer === undefined) return { verified: false, reason: "timeout" };
	if (answer.trim() === "") return { verified: false, reason: "cancelled" };

	const expected = Buffer.from(expectedProof(secret, nonce, options.sessionId), "utf8");
	const actual = Buffer.from(answer.trim(), "utf8");
	// Length-check first: timingSafeEqual throws on a mismatch, and the length
	// of the expected proof is not a secret.
	if (actual.length !== expected.length) return { verified: false, reason: "bad-mac" };
	if (!timingSafeEqual(actual, expected)) return { verified: false, reason: "bad-mac" };

	return { verified: true };
}

/**
 * Provision the secret. `pi-enclave attend-secret`.
 *
 * Written `0600`, and the *path* is printed rather than the value: a secret
 * echoed to a terminal is a secret in the scrollback, in the shell history of
 * whatever ran it, and in any CI log that captured the output.
 */
export function provisionSecret(path: string, write = writeFileSync): string {
	const secret = randomBytes(SECRET_BYTES).toString("base64");
	write(path, `${secret}\n`, { mode: 0o600 });
	return path;
}

export function describeHandshakeFailure(reason: Exclude<HandshakeResult, { verified: true }>["reason"]): string {
	switch (reason) {
		case "no-secret":
			return "no attendance secret is provisioned; run `pi-enclave attend-secret` and give the value to the client";
		case "insecure-secret":
			return "the attendance secret file is not a 0600 regular file owned by you, so it is not trusted";
		case "timeout":
			return "the client did not answer the attendance challenge (it may not implement the handshake)";
		case "cancelled":
			return "the client declined the attendance challenge";
		case "bad-mac":
			return "the client's answer to the attendance challenge did not verify";
	}
}
