export type SemanticUnavailableReason = "config" | "missing_key" | "timeout" | "http" | "network" | "invalid_response";

export class SemanticUnavailableError extends Error {
  constructor(public readonly reason: SemanticUnavailableReason, public readonly status?: number) {
    const messages: Record<SemanticUnavailableReason, string> = {
      config: "Invalid semantic configuration: choose anthropic or openai, supply an explicit OpenAI-compatible model, a valid base URL and a positive timeoutMs.",
      missing_key: "Semantic analysis requires an API key unless using a localhost OpenAI-compatible endpoint.",
      timeout: "Semantic analysis exceeded its deadline.",
      http: "Semantic provider returned an HTTP error.",
      network: "Semantic provider could not be reached.",
      invalid_response: "Semantic provider returned an invalid verdict.",
    };
    // Only the status code is added: provider bodies can echo request headers.
    super(status ? `${messages[reason]} (HTTP ${status})` : messages[reason]);
    this.name = "SemanticUnavailableError";
  }
}

export interface SemanticConfig {
  provider: "anthropic" | "openai";
  model: string;
  baseUrl: string;
  apiKey?: string;
  timeoutMs: number;
  runs?: number;
  maxChars?: number;
  cache?: boolean;
}

export function isLocal(url: URL): boolean {
  return ["localhost", "127.0.0.1", "[::1]"].includes(url.hostname);
}

export function validateConfig(config: SemanticConfig): void {
  let url: URL;
  try { url = new URL(config.baseUrl); } catch { throw new SemanticUnavailableError("config"); }
  if (!["anthropic", "openai"].includes(config.provider) || !config.model?.trim() ||
      // A key must not cross the network in clear text; plain http is for local models.
      !(url.protocol === "https:" || (url.protocol === "http:" && isLocal(url))) || url.username || url.password || url.search || url.hash ||
      !Number.isFinite(config.timeoutMs) || config.timeoutMs <= 0 || config.timeoutMs > 2_147_483_647 ||
      !Number.isInteger(config.runs ?? 1) || (config.runs ?? 1) < 1 || (config.runs ?? 1) > 5 ||
      !Number.isInteger(config.maxChars ?? 60_000) || (config.maxChars ?? 60_000) < 1) {
    throw new SemanticUnavailableError("config");
  }
  if (!config.apiKey?.trim() && !(config.provider === "openai" && isLocal(url))) {
    throw new SemanticUnavailableError("missing_key");
  }
}

export function resolveSemanticConfig(
  env: Record<string, string | undefined>, overrides: Partial<SemanticConfig> = {}
): SemanticConfig {
  // An exported-but-empty variable means unset, as in most shells' configs.
  env = Object.fromEntries(Object.entries(env).filter(([, value]) => value?.trim()));
  const provider = overrides.provider ?? env.CLAWVET_LLM_PROVIDER ?? (env.OPENAI_API_KEY && !env.ANTHROPIC_API_KEY ? "openai" : "anthropic");
  const config: SemanticConfig = {
    provider: provider as SemanticConfig["provider"],
    model: overrides.model ?? env.CLAWVET_LLM_MODEL ?? (provider === "anthropic" ? "claude-haiku-5-5" : ""),
    baseUrl: overrides.baseUrl ?? env.CLAWVET_LLM_BASE_URL ?? (provider === "anthropic" ? "https://api.anthropic.com/v1" : "https://api.openai.com/v1"),
    apiKey: overrides.apiKey ?? env.CLAWVET_LLM_API_KEY ?? (provider === "anthropic" ? env.ANTHROPIC_API_KEY : env.OPENAI_API_KEY),
    timeoutMs: overrides.timeoutMs!,
    runs: overrides.runs ?? 1,
    maxChars: overrides.maxChars ?? 60_000,
    cache: overrides.cache ?? false,
  };
  validateConfig(config);
  return config;
}
