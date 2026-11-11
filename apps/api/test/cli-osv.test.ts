import { afterEach, describe, expect, it, vi } from "vitest";
import { mkdtemp, rm, readdir, stat, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { queryOsv } from "../../../packages/cli/src/osv.js";
const dep = (name = "example", ecosystem: "PyPI" | "npm" = "PyPI") => ({ name, ecosystem, version: "1.0.0", path: "requirements.txt", line: 17 });
const json = (value: unknown) => new Response(JSON.stringify(value), { status: 200 });
const dirs: string[] = [];
afterEach(async () => { vi.unstubAllEnvs(); for (const dir of dirs.splice(0)) await rm(dir, { recursive: true, force: true }); });
const mock = (detail: Record<string, unknown>) => vi.fn<typeof fetch>(async (_url, init) => init?.method === "POST" ? json({ results: [{ vulns: [{ id: detail.id }] }] }) : json(detail));

describe("OSV lookup", () => {
  it.each(["id", "alias"])("marks MAL %s matches as disqualifying critical", async (kind) => {
    const detail = { id: kind === "id" ? "MAL-TEST" : "GHSA-TEST", aliases: ["MAL-ALIAS"], summary: "Test summary", affected: [{ ranges: [{ events: [{ fixed: "2.0.0" }] }] }] };
    const fetchImpl = mock(detail);
    const result = await queryOsv([dep()], { fetchImpl });
    expect(result.errors).toEqual([]);
    expect(result.findings[0]).toMatchObject({ analysisPass: "osv", category: "dependency_risk", severity: "critical", disqualifying: true, lineNumber: 17, evidence: "example==1.0.0", title: `Known malicious dependency: ${detail.id}` });
    expect(result.findings[0].description).toContain("Fixed versions: 2.0.0");
    expect(JSON.parse(fetchImpl.mock.calls[0][1]!.body as string)).toEqual({ queries: [{ package: { ecosystem: "PyPI", name: "example" }, version: "1.0.0" }] });
  });
  it.each([["9.0", "critical"], ["7.0", "high"], ["4.0", "medium"], ["3.9", "low"], ["CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "critical"], ["CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N", "medium"], ["AV:N/AC:L/Au:N/C:P/I:P/A:P", "high"]])("maps %s CVSS to %s", async (score, severity) => {
    const result = await queryOsv([dep("@scope/example", "npm")], { fetchImpl: mock({ id: "TEST", severity: [{ type: "CVSS_V3", score }] }) });
    expect(result.findings[0]).toMatchObject({ severity, evidence: "@scope/example@1.0.0" });
  });
  it.each([[{ severity: "HIGH" }, "high"], [{}, "medium"]])("uses database severity or medium fallback", async (database_specific, severity) => {
    const result = await queryOsv([dep()], { fetchImpl: mock({ id: "TEST", database_specific }) });
    expect(result.findings[0].severity).toBe(severity);
  });
  it("reads CVSS from affected-package severity", async () => {
    const result = await queryOsv([dep()], { fetchImpl: mock({ id: "TEST", affected: [{ severity: [{ score: "9.8" }] }] }) });
    expect(result.findings[0].severity).toBe("critical");
  });
  it("returns deadline errors even if fetch ignores the signal", async () => {
    const fetchImpl = vi.fn<typeof fetch>(() => new Promise(() => {}));
    const result = await queryOsv([dep()], { timeoutMs: 10, fetchImpl });
    expect(result.errors.join()).toMatch(/deadline/);
    expect((fetchImpl.mock.calls[0][1]?.signal as AbortSignal).aborted).toBe(true);
  });
  it("keeps MAL evidence when detail fetch fails", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async (_url, init) => { if (init?.method === "POST") return json({ results: [{ vulns: [{ id: "MAL-TEST" }] }] }); throw new Error("offline"); });
    const result = await queryOsv([dep()], { fetchImpl });
    expect(result.findings[0].disqualifying).toBe(true);
    expect(result.errors).toEqual(["offline"]);
  });
  it.each([null, { results: [] }, { results: [{ vulns: [null] }] }])("handles bad responses without throwing", async (response) => {
    const result = await queryOsv([dep()], { fetchImpl: vi.fn(async () => json(response)) });
    expect(result.errors.length).toBeGreaterThan(0);
  });
  it("handles malformed detail responses without throwing", async () => {
    const result = await queryOsv([dep()], { fetchImpl: mock({ id: "TEST", affected: [{ ranges: "invalid" }] }) });
    expect(result.errors.length).toBeGreaterThan(0);
  });
  it("caches batch results and details with private permissions and expiration", async () => {
    const directory = await mkdtemp(join(tmpdir(), "clawvet-osv-")); dirs.push(directory); vi.stubEnv("XDG_CACHE_HOME", directory);
    const fetchImpl = mock({ id: "TEST", summary: "Test" });
    const first = await queryOsv([dep()], { cache: true, fetchImpl });
    fetchImpl.mockClear();
    expect(await queryOsv([dep()], { cache: true, fetchImpl })).toEqual(first);
    expect(fetchImpl).not.toHaveBeenCalled();
    const cacheDir = join(directory, "clawvet", "osv");
    const files = await readdir(cacheDir);
    expect(files).toHaveLength(2);
    for (const file of files) {
      const path = join(cacheDir, file);
      expect((await stat(path)).mode & 0o777).toBe(0o600);
      const entry = JSON.parse(await readFile(path, "utf8"));
      entry.time = Date.now() - 2 * 24 * 60 * 60 * 1000;
      await writeFile(path, JSON.stringify(entry));
    }
    await queryOsv([dep()], { cache: true, fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1]?.method).toBe("POST");
    fetchImpl.mockClear();
    for (const file of files.filter((f) => f.startsWith("vuln-"))) {
      const path = join(cacheDir, file);
      const entry = JSON.parse(await readFile(path, "utf8"));
      entry.time = Date.now() - 8 * 24 * 60 * 60 * 1000;
      await writeFile(path, JSON.stringify(entry));
    }
    await queryOsv([dep()], { cache: true, fetchImpl });
    expect(fetchImpl).toHaveBeenCalledTimes(1);
    expect(fetchImpl.mock.calls[0][1]?.method).toBeUndefined();
  });
  it("batches queries, deduplicates details, and limits concurrency", async () => {
    let active = 0; let maximum = 0;
    const batchSizes: number[] = [];
    const fetchImpl = vi.fn<typeof fetch>(async (url, init) => {
      if (init?.method === "POST") {
        const queries = JSON.parse(init.body as string).queries;
        batchSizes.push(queries.length);
        return json({ results: queries.map((_: unknown, i: number) => ({ vulns: [{ id: `TEST-${i % 20}` }, { id: `TEST-${i % 20}` }] })) });
      }
      active++; maximum = Math.max(maximum, active);
      await new Promise((resolve) => setTimeout(resolve, 2)); active--;
      return json({ id: String(url).split("/").pop() });
    });
    const result = await queryOsv(Array.from({ length: 1001 }, (_, i) => dep(`pkg${i}`)), { fetchImpl });
    expect(batchSizes).toEqual([1000, 1]);
    expect(maximum).toBe(8);
    expect(fetchImpl).toHaveBeenCalledTimes(22);
    expect(result.findings).toHaveLength(1001);
    expect(result.errors).toEqual([]);
  });
  it("deduplicates identical inputs and performs no requests for no inputs", async () => {
    const fetchImpl = mock({ id: "TEST" });
    expect(await queryOsv([], { fetchImpl })).toEqual({ findings: [], errors: [] });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect((await queryOsv([dep(), dep()], { fetchImpl })).findings).toHaveLength(1);
  });
});
