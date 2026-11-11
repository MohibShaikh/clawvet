import { SemanticUnavailableError, type SemanticConfig } from "./config.js";

// A verdict is a few kilobytes. A larger body is an error, never parsed: parsing
// is synchronous and would hold the deadline timer off.
export const RESPONSE_MAX_BYTES = 1024 * 1024;

async function readCapped(response: Response): Promise<string> {
  const reader = response.body?.getReader();
  if (!reader) throw new Error("empty body");
  const chunks: Uint8Array[] = [];
  let size = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    size += value.byteLength;
    if (size > RESPONSE_MAX_BYTES) { await reader.cancel().catch(() => {}); throw new Error("response too large"); }
    chunks.push(value);
  }
  return new TextDecoder().decode(Buffer.concat(chunks));
}

export async function requestVerdict(config: SemanticConfig, prompt: { system: string; user: string }, signal: AbortSignal): Promise<string> {
  const anthropic = config.provider === "anthropic";
  const headers: Record<string, string> = { "content-type": "application/json" };
  if (anthropic) {
    headers["x-api-key"] = config.apiKey!;
    headers["anthropic-version"] = "2023-06-01";
  } else if (config.apiKey) headers.authorization = `Bearer ${config.apiKey}`;
  let response: Response;
  try {
    response = await fetch(`${config.baseUrl.replace(/\/$/, "")}/${anthropic ? "messages" : "chat/completions"}`, {
      method: "POST", headers, signal, redirect: "error",
      body: JSON.stringify({
        model: config.model, max_tokens: 4096,
        ...(anthropic ? { system: prompt.system } : {}),
        messages: [...(anthropic ? [] : [{ role: "system", content: prompt.system }]), { role: "user", content: prompt.user }],
      }),
    });
  } catch {
    throw new SemanticUnavailableError(signal.aborted ? "timeout" : "network");
  }
  if (!response.ok) throw new SemanticUnavailableError("http", response.status);
  try {
    const body = JSON.parse(await readCapped(response)) as { content?: { type: string; text: string }[]; choices?: { message?: { content?: string } }[] };
    const text = anthropic
      ? (Array.isArray(body.content) ? body.content.filter((block: { type: string }) => block.type === "text").map((block: { text: string }) => block.text).join("") : undefined)
      : body.choices?.[0]?.message?.content;
    if (typeof text !== "string" || !text) throw new Error();
    return text;
  } catch {
    throw new SemanticUnavailableError(signal.aborted ? "timeout" : "invalid_response");
  }
}
