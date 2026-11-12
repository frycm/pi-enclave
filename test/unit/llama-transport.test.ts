/**
 * The classifier reviewer transport on llama.cpp (#26), against a fake router
 * that answers like llama.cpp's server (tools/server/server-models.cpp and
 * server-context.cpp): `GET /models` lists the model and its spawn arguments,
 * `GET /props?model=` is answered by the model's child with `model_path`,
 * `build_info` and the slot context, and the classification endpoints are the
 * ones pi-ai's `llama-cpp-classify` and System One modules use. The real pi-ai
 * modules run against it; nothing in the transport is mocked.
 */
import { chmodSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { createServer, type Server } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import type { ModelRegistry } from "@earendil-works/pi-coding-agent";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { defaultProfile } from "../../src/config/defaults.ts";
import { canonicalize } from "../../src/policy/canonical.ts";
import { evalReviewer } from "../../src/reviewer/eval.ts";
import {
	bindReviewerClassifier,
	type ClassifierRuntimeModel,
	ggufDigest,
	resolveReviewerClassifier,
	reviewerClassifierDigest,
} from "../../src/reviewer/llama.ts";
import { CLASSIFIER_ALLOW_FLOOR, CLASSIFIER_ALLOW_MARGIN } from "../../src/reviewer/probabilities.ts";
import { buildReviewerPrompt, reviewerRulebook } from "../../src/reviewer/prompt.ts";
import { readQualification, writeQualification } from "../../src/reviewer/qualification.ts";
import { IsolatedReviewer } from "../../src/reviewer/reviewer.ts";
import { prepareQualifiedReviewer } from "../../src/reviewer/setup.ts";

const PROFILE = defaultProfile({ cwd: "/work", home: "/home/u", tmp: "/tmp", agentDir: "/home/u/.pi/agent" });
const PROMPT = buildReviewerPrompt(reviewerRulebook(PROFILE.review, new Map()));
const THRESHOLDS = { allow: 0.9, deny: 0.5, temperature: 1 };

/** The probabilities the fake model gives, per question, from the rendered prompt. */
type Scenario = (question: "authorized" | "decision" | "risk", prompt: string) => number[];

let server: Server;
let root: string;
let directory: string;
let gguf: string;
let status: string;
let modelPath: string;
let nCtx: number;
let port: number;
let scenario: Scenario;
let onCompletion: (() => void) | undefined;
let redirect: boolean;
let received: { url: string; authorization?: string; body: Record<string, unknown> }[];

// A vocabulary in which every answer label is one token, as in real chat models.
const WORDS = ["Yes", "No"];
function tokenize(content: string): number[] {
	const tokens: number[] = [];
	for (let index = 0; index < content.length; ) {
		const word = WORDS.find((entry) => content.startsWith(entry, index));
		if (word) {
			tokens.push(1000 + WORDS.indexOf(word));
			index += word.length;
		} else {
			tokens.push(content.charCodeAt(index));
			index++;
		}
	}
	return tokens;
}

function question(prompt: string): { id: "authorized" | "decision" | "risk"; labels: number[] } {
	const tail = prompt.slice(prompt.lastIndexOf("Question:"));
	if (tail.includes("Answer Yes or No.")) return { id: "authorized", labels: [1000, 1001] };
	if (tail.includes("allow: ")) return { id: "decision", labels: [65, 66, 67] };
	return { id: "risk", labels: [65, 66, 67, 68] };
}

beforeEach(async () => {
	directory = mkdtempSync(join(tmpdir(), "pi-enclave-llama-"));
	gguf = join(directory, "qwen3-4b-Q4_K_M.gguf");
	writeFileSync(gguf, "GGUF fake weights v1");
	modelPath = gguf;
	status = "loaded";
	nCtx = 8192;
	port = 41_001;
	redirect = false;
	onCompletion = undefined;
	received = [];
	// allow / ask / deny ; low / medium / high / critical
	scenario = (id) =>
		id === "authorized" ? [0.9, 0.1] : id === "decision" ? [0.95, 0.03, 0.02] : [0.7, 0.2, 0.05, 0.05];
	server = createServer(async (req, res) => {
		const chunks = [];
		for await (const chunk of req) chunks.push(chunk);
		const body = JSON.parse(Buffer.concat(chunks).toString() || "{}") as Record<string, unknown>;
		received.push({
			url: req.url ?? "",
			body,
			...(req.headers.authorization ? { authorization: req.headers.authorization } : {}),
		});
		res.setHeader("Content-Type", "application/json");
		const url = new URL(req.url ?? "/", "http://fake");
		if (redirect) {
			res.writeHead(302, { Location: "/elsewhere" });
			res.end();
			return;
		}
		if (url.pathname === "/models") {
			res.end(
				JSON.stringify({
					object: "list",
					data: [
						{
							id: "qwen3-4b",
							status: {
								value: status,
								args: ["/opt/llama/llama-server", "--model", gguf, "--port", String(port), "--ctx-size", String(nCtx)],
							},
							architecture: { input_modalities: ["text"], output_modalities: ["text"] },
							source: "models_dir",
						},
					],
				}),
			);
		} else if (url.pathname === "/props") {
			res.end(
				JSON.stringify(
					url.searchParams.get("model") === "qwen3-4b"
						? {
								model_path: modelPath,
								build_info: "b7100-abcdef0",
								default_generation_settings: { n_ctx: nCtx },
								chat_template: "{{ messages }}",
								total_slots: 1,
							}
						: { role: "router", model_path: "none", build_info: "b7100-abcdef0" },
				),
			);
		} else if (url.pathname === "/tokenize") {
			res.end(JSON.stringify({ tokens: tokenize(String(body.content)) }));
		} else if (url.pathname === "/apply-template") {
			const messages = body.messages as { role: string; content: string }[];
			res.end(JSON.stringify({ prompt: `${messages.map((m) => `<${m.role}>${m.content}`).join("\n")}\n` }));
		} else if (url.pathname === "/completion") {
			onCompletion?.();
			const prompt = String(body.prompt);
			const { id, labels } = question(prompt);
			const probabilities = scenario(id, prompt);
			res.end(
				JSON.stringify({
					completion_probabilities: [
						{
							top_logprobs: labels.map((token, index) => ({ id: token, logprob: Math.log(probabilities[index] ?? 0) })),
						},
					],
				}),
			);
		} else {
			res.writeHead(404);
			res.end("{}");
		}
	});
	await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
	root = `http://127.0.0.1:${(server.address() as AddressInfo).port}`;
});

afterEach(async () => {
	server.closeAllConnections();
	await new Promise<void>((resolve) => server.close(() => resolve()));
	rmSync(directory, { recursive: true, force: true });
});

function classifierModel(overrides: Partial<ClassifierRuntimeModel> = {}): ClassifierRuntimeModel {
	return {
		type: "classifier",
		provider: "llama.cpp",
		id: "qwen3-4b",
		name: "qwen3-4b",
		api: "llama-cpp-classify",
		// The registry's catalog entry is stale; auth resolution supplies the real server.
		baseUrl: "http://wrong-server.invalid",
		input: ["text"],
		cost: { input: 0, output: 0, cacheRead: 0, cacheWrite: 0 },
		contextWindow: 8192,
		...overrides,
	};
}

function registryFor(model: ClassifierRuntimeModel, baseUrl = `${root}/v1`): ModelRegistry {
	return {
		find: () => undefined,
		getModelOfType: (type: string, provider: string, id: string) =>
			type === "classifier" && provider === model.provider && id === model.id ? model : undefined,
		hasConfiguredAuth: () => true,
		// As pi's llama.cpp provider resolves it: the router's /v1 URL and its key.
		getApiKeyAndHeaders: async () => ({ ok: true, baseUrl, apiKey: "router-key" }),
		classify: async () => {
			throw new Error("the reviewer must not re-resolve auth through ModelRegistry.classify");
		},
	} as unknown as ModelRegistry;
}

function writeAction(content: string) {
	return canonicalize({
		tool: "write",
		input: { path: "/workspace/build/report.txt", content },
		cwd: "/workspace",
		home: "/home/eval",
		profileName: PROFILE.name,
		writableRoots: ["/workspace"],
	});
}

async function bound(model = classifierModel(), registry = registryFor(model)) {
	const resolved = resolveReviewerClassifier(registry, "llama.cpp/qwen3-4b");
	const identity = await reviewerClassifierDigest(model, registry);
	return { resolved, identity, classifier: bindReviewerClassifier(resolved, identity, THRESHOLDS), registry };
}

function reviewer(classifier: Awaited<ReturnType<typeof bound>>["classifier"]) {
	return new IsolatedReviewer({
		profile: PROFILE,
		prompt: PROMPT,
		primary: classifier,
		timeoutMs: 5_000,
		maxAttempts: 1,
		evidence: { attended: "off" },
	});
}

describe("llama.cpp identity without Ollama", () => {
	it("binds the GGUF digest, server build, slot context and load arguments", async () => {
		const model = classifierModel();
		const registry = registryFor(model);
		const identity = await reviewerClassifierDigest(model, registry);
		expect(identity).toMatch(/^llama\.cpp:sha256:[0-9a-f]{64}$/);
		await expect(reviewerClassifierDigest(model, registry)).resolves.toBe(identity);
		// Nothing outside the router: no Ollama endpoints were asked.
		expect(received.every((entry) => !entry.url.includes("/api/"))).toBe(true);
		expect(received.some((entry) => entry.url === "/props?model=qwen3-4b")).toBe(true);
		expect(received.every((entry) => entry.authorization === "Bearer router-key")).toBe(true);
	});

	it("ignores the per-spawn port but not the context size", async () => {
		const model = classifierModel();
		const registry = registryFor(model);
		const identity = await reviewerClassifierDigest(model, registry);
		port = 41_002;
		await expect(reviewerClassifierDigest(model, registry)).resolves.toBe(identity);
		nCtx = 4096;
		await expect(reviewerClassifierDigest(model, registry)).resolves.not.toBe(identity);
	});

	it("changes when the weights change, even at the same size and path", async () => {
		const model = classifierModel();
		const registry = registryFor(model);
		const identity = await reviewerClassifierDigest(model, registry);
		writeFileSync(gguf, "GGUF fake weights v2");
		await expect(reviewerClassifierDigest(model, registry)).resolves.not.toBe(identity);
	});

	it("does not take the catalog's context window into the identity", async () => {
		const registry = registryFor(classifierModel());
		const identity = await reviewerClassifierDigest(classifierModel(), registry);
		await expect(reviewerClassifierDigest(classifierModel({ contextWindow: 128_000 }), registry)).resolves.toBe(
			identity,
		);
	});

	it("hashes every shard of a split model, and refuses a missing one", async () => {
		const first = join(directory, "big-00001-of-00002.gguf");
		writeFileSync(first, "shard one");
		writeFileSync(join(directory, "big-00002-of-00002.gguf"), "shard two");
		const shards = await ggufDigest(first);
		expect(shards.map((entry) => entry.name)).toEqual(["big-00001-of-00002.gguf", "big-00002-of-00002.gguf"]);
		writeFileSync(join(directory, "big-00002-of-00002.gguf"), "shard two, changed");
		expect((await ggufDigest(first))[1]?.sha256).not.toBe(shards[1]?.sha256);
		rmSync(join(directory, "big-00002-of-00002.gguf"));
		await expect(ggufDigest(first)).rejects.toThrow("cannot stat the llama.cpp model file");
	});

	it.skipIf(process.getuid?.() === 0)("refuses weights the pi user cannot read", async () => {
		chmodSync(gguf, 0o000);
		const model = classifierModel();
		await expect(reviewerClassifierDigest(model, registryFor(model))).rejects.toThrow("not readable by the pi user");
	});

	it.each([
		["the router does not report a file", () => (modelPath = "none"), "did not report the model file"],
		["the reported path is relative", () => (modelPath = "models/qwen.gguf"), "not absolute"],
		["the model is not loaded", () => (status = "unloaded"), "load it with /llama"],
		["the path is a directory", () => (modelPath = directory), "not a regular file"],
	])("refuses when %s", async (_label, change, message) => {
		change();
		const model = classifierModel();
		await expect(reviewerClassifierDigest(model, registryFor(model))).rejects.toThrow(message);
	});

	it("refuses a router off loopback, a non-llama.cpp classifier and a redirect", async () => {
		const model = classifierModel();
		await expect(reviewerClassifierDigest(model, registryFor(model, "http://10.0.0.5:8080/v1"))).rejects.toThrow(
			"must be served on loopback",
		);
		const jev = classifierModel({ provider: "typesafe", id: "jev-latest", api: "typesafe-system-one" });
		expect(() => resolveReviewerClassifier(registryFor(jev), "typesafe/jev-latest")).toThrow(
			"supports llama.cpp models only",
		);
		redirect = true;
		await expect(reviewerClassifierDigest(model, registryFor(model))).rejects.toThrow();
	});

	it("refuses a model the registry lists only as a chat model", () => {
		const registry = registryFor(classifierModel({ id: "other" }));
		expect(() => resolveReviewerClassifier(registry, "llama.cpp/qwen3-4b")).toThrow("not a classifier model");
	});
});

describe("classification through the pinned snapshot", () => {
	it("asks the three questions with the evidence as state and maps probabilities to a verdict", async () => {
		const { classifier } = await bound();
		const result = await reviewer(classifier).review({ action: writeAction("routine report\n"), trigger: "mutating" });
		if (!result.ok) throw new Error(result.reason);
		expect(result.modelReview.decision).toBe("allow");
		expect(result.modelReview.reason).toContain("P(allow) 95.0% >= 90.0%");
		expect(result.probabilities?.decision.allow).toBeCloseTo(0.95, 6);
		expect(result.probabilities?.authorized).toBeCloseTo(0.9, 6);
		const completions = received.filter((entry) => entry.url === "/completion");
		expect(completions).toHaveLength(3);
		// Pinned to the auth-resolved router, one label read, no generation.
		for (const entry of completions) {
			expect(entry.body).toMatchObject({ model: "qwen3-4b", n_predict: 1 });
			expect(String(entry.body.prompt)).toContain('"hash": "sha256:');
		}
	});

	it("asks when the model is unsure and denies on a deny majority", async () => {
		const { classifier } = await bound();
		scenario = (id) =>
			id === "decision" ? [0.6, 0.3, 0.1] : id === "authorized" ? [0.5, 0.5] : [0.25, 0.25, 0.25, 0.25];
		const unsure = await reviewer(classifier).review({ action: writeAction("x\n"), trigger: "mutating" });
		expect(unsure.ok && unsure.modelReview.decision).toBe("ask");
		scenario = (id) =>
			id === "decision" ? [0.1, 0.2, 0.7] : id === "authorized" ? [0.1, 0.9] : [0.001, 0.001, 0.997, 0.001];
		const deny = await reviewer(classifier).review({ action: writeAction("x\n"), trigger: "mutating" });
		expect(deny.ok && deny.modelReview).toMatchObject({ decision: "deny", risk: "high" });
	});

	it("refuses a verdict when the weights change during classification", async () => {
		const { classifier } = await bound();
		let calls = 0;
		onCompletion = () => {
			if (++calls === 1) writeFileSync(gguf, "GGUF swapped weights");
		};
		const result = await reviewer(classifier).review({ action: writeAction("x\n"), trigger: "mutating" });
		expect(result).toMatchObject({ ok: false, kind: "unavailable" });
		if (!result.ok) expect(result.reason).toContain("identity changed during classification");
	});

	it("refuses to classify on an identity other than the bound one", async () => {
		const { resolved } = await bound();
		const stale = bindReviewerClassifier(resolved, "llama.cpp:sha256:stale", THRESHOLDS);
		const result = await reviewer(stale).review({ action: writeAction("x\n"), trigger: "mutating" });
		expect(result.ok).toBe(false);
		if (!result.ok) expect(result.reason).toContain("requalification required");
		expect(received.some((entry) => entry.url === "/completion")).toBe(false);
	});

	it("routes a native decision model to llama.cpp's System One endpoint", async () => {
		const model = classifierModel({ api: "typesafe-system-one" });
		const { classifier } = await bound(model);
		const result = await reviewer(classifier).review({ action: writeAction("x\n"), trigger: "mutating" });
		// The fake router has no /v1/systemone: the request is made there and fails closed.
		expect(result.ok).toBe(false);
		expect(received.some((entry) => entry.url === "/v1/systemone")).toBe(true);
	});
});

describe("qualification on the classifier transport", () => {
	function corpusScenario(injectedAllow: number): Scenario {
		return (id, prompt) => {
			if (id !== "decision") return id === "authorized" ? [0.5, 0.5] : [0.7, 0.2, 0.05, 0.05];
			const allow = prompt.includes("routine generated report") ? 0.97 : injectedAllow;
			return [allow, (1 - allow) / 2, (1 - allow) / 2];
		};
	}

	it("runs end to end, chooses the allow threshold above every injected case and stores it", async () => {
		scenario = corpusScenario(0.4);
		const { classifier, identity, registry } = await bound();
		const record = await evalReviewer({
			model: "llama.cpp/qwen3-4b",
			modelDigest: identity,
			profile: PROFILE,
			prompt: PROMPT,
			completion: classifier,
			timeoutMs: 10_000,
		});
		expect(record).toMatchObject({ passed: true, transport: "classifier", promptHash: PROMPT.classifier.promptHash });
		expect(record.sampling.trials).toBe(1);
		expect(record.metrics).toMatchObject({ injectedAllows: 0, benignFalseDenials: 0, errors: 0 });
		expect(record.metrics.maxInjectedAllow).toBeCloseTo(0.4, 6);
		expect(record.thresholds?.allow).toBe(CLASSIFIER_ALLOW_FLOOR);

		// The record is what session start reads, and its thresholds are the ones used.
		const qualified = mkdtempSync(join(tmpdir(), "pi-enclave-qualified-"));
		chmodSync(qualified, 0o700);
		try {
			writeQualification(qualified, record);
			const profile = {
				...PROFILE,
				auto: true,
				reviewer: { ...PROFILE.reviewer, model: "llama.cpp/qwen3-4b", transport: "classifier" as const },
			};
			const setup = await prepareQualifiedReviewer(profile, new Map(), registry, qualified);
			expect(setup?.primary).toMatchObject({ kind: "classifier", thresholds: record.thresholds });
			// The same record does not qualify the chat transport.
			const asChat = readQualification(qualified, { ...record, transport: "chat" });
			expect(asChat.ok).toBe(false);
		} finally {
			rmSync(qualified, { recursive: true, force: true });
		}
	});

	it("puts the threshold a margin above an allow-like injected case", async () => {
		scenario = corpusScenario(0.9);
		const { classifier, identity } = await bound();
		const record = await evalReviewer({
			model: "llama.cpp/qwen3-4b",
			modelDigest: identity,
			profile: PROFILE,
			prompt: PROMPT,
			completion: classifier,
			timeoutMs: 10_000,
		});
		expect(record.thresholds?.allow).toBeCloseTo(0.9 + CLASSIFIER_ALLOW_MARGIN, 6);
		expect(record).toMatchObject({ passed: true, metrics: { injectedAllows: 0 } });
	});

	it("fails when no threshold separates injected from benign cases", async () => {
		scenario = corpusScenario(0.97);
		const { classifier, identity } = await bound();
		const record = await evalReviewer({
			model: "llama.cpp/qwen3-4b",
			modelDigest: identity,
			profile: PROFILE,
			prompt: PROMPT,
			completion: classifier,
			timeoutMs: 10_000,
		});
		expect(record.passed).toBe(false);
		expect(record.metrics.benignFalseDenials).toBe(20);
	});
});
