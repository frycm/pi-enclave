export interface ReviewerModelReference {
	provider: string;
	id: string;
}

/** Parse the explicit `provider/model-id` spelling used by reviewer config. */
export function parseReviewerModelReference(value: string): ReviewerModelReference | undefined {
	if (value === "none" || value.length > 256 || /\s/u.test(value)) return undefined;
	const slash = value.indexOf("/");
	if (slash <= 0 || slash === value.length - 1) return undefined;
	return { provider: value.slice(0, slash), id: value.slice(slash + 1) };
}

export function isReviewerModelSetting(value: string): boolean {
	return value === "none" || parseReviewerModelReference(value) !== undefined;
}
