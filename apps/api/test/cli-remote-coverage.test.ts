import { afterEach, expect, it, vi } from "vitest";
import { scanCommand } from "../../../packages/cli/src/commands/scan.js";

afterEach(() => { vi.restoreAllMocks(); vi.unstubAllGlobals(); vi.unstubAllEnvs(); });

it("reports a remote manifest as incomplete and exits 1 instead of approving the package", async () => {
  vi.stubEnv("CLAWVET_TELEMETRY", "off");
  const content = "---\nname: remote-coverage\ndescription: Say hello.\n---\nSay hello.";
  const fetchMock = vi.fn(async () => new Response(JSON.stringify({ skill: { description: content } })));
  vi.stubGlobal("fetch", fetchMock);
  vi.spyOn(process, "exit").mockImplementation(() => { throw new Error("EXIT:1"); });
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  const output = vi.spyOn(console, "log").mockImplementation(() => {});
  // The report is printed, then the exit code is set rather than process.exit
  // called, so piped output is not cut off.
  await scanCommand("remote-coverage", { remote: true, format: "json" });
  expect(process.exitCode).toBe(1);
  process.exitCode = undefined;
  const result = JSON.parse(output.mock.calls[0][0]);
  expect(result).toMatchObject({ status: "failed", recommendation: "block", coverage: { complete: false } });
  expect(result.coverage.issues[0].reason).toMatch(/only the manifest/);
  expect(fetchMock).toHaveBeenCalledTimes(1);
});

it("cancels oversized remote responses before scanning", async () => {
  vi.stubEnv("CLAWVET_TELEMETRY", "off");
  const cancel = vi.fn();
  vi.stubGlobal("fetch", vi.fn(async () => new Response(new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(256 * 1024 + 1)); },
    cancel,
  }))));
  vi.spyOn(process, "exit").mockImplementation(() => { throw new Error("EXIT:1"); });
  vi.spyOn(process.stderr, "write").mockImplementation(() => true);
  vi.spyOn(console, "error").mockImplementation(() => {});
  const output = vi.spyOn(console, "log").mockImplementation(() => {});
  await expect(scanCommand("too-large", { remote: true, format: "json" })).rejects.toThrow("EXIT:1");
  expect(cancel).toHaveBeenCalledTimes(3); // all three manifest sources are bounded
  expect(output).not.toHaveBeenCalled();
});
