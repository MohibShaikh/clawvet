import type { BundledFile, Capability } from "@clawvet/shared";

export const PERMISSION_LABELS: Record<Capability["kind"], string> = {
  network: "Network", secret: "Secrets", env: "Env vars", persistence: "Persistence", behavior: "Behaviour",
};

/**
 * Capability lines are positions in the assembled bundle; report them the way
 * findings are reported, as a file and a line inside it.
 */
export function locateCapabilities(capabilities: Capability[] | undefined, files?: BundledFile[]): Capability[] | undefined {
  if (!capabilities || !files?.length) return capabilities;
  return capabilities.map((c) => {
    const file = c.line != null ? files.find((f) => c.line! >= f.startLine && c.line! <= f.endLine) : undefined;
    return file ? { ...c, file: file.path, line: c.line! - file.startLine + 1 } : c;
  });
}

/** One permission for a person to read: "Secrets ~/.aws/credentials (scripts/fetch.py:41)". */
export function describePermission(c: Capability): string {
  const where = c.file ? ` (${c.file}${c.line ? `:${c.line}` : ""})` : "";
  return `${PERMISSION_LABELS[c.kind]} ${c.value}${where}`;
}
