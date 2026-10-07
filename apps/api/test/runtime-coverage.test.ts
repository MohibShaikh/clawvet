import { describe, expect, it } from "vitest";
import { inspectRuntimeCoverage } from "../../../packages/cli/src/runtime-coverage.js";

describe("runtime inspection boundaries", () => {
  it.each([
    'bash -e "$SCRIPT"',
    'bash -lc "$CODE"',
    'python -m "$MODULE"',
    '"$RUNNER" --flag',
    './scripts/*.sh',
    'bash <(curl https://example.invalid/script)',
    'bash -c `curl https://example.invalid/script`',
    'node --import "$MODULE"',
    'import(moduleName)',
    'import(`./${name}.js`)',
    'require("./" + name)',
    'exec(requests.get(url).text)',
    'new Function(await response.text())()',
    'subprocess.run(["python", script])',
    'child_process.execFile("bash", [path])',
    'importlib.spec_from_file_location("helper", path)',
    'powershell -EncodedCommand ZWNobyBoaQ==',
    'powershell.exe -File "$SCRIPT"',
    'cmd.exe /c "%SCRIPT%"',
  ])("marks computed/loaded code incomplete: %s", (source) => {
    expect(inspectRuntimeCoverage(source).issues.length).toBeGreaterThan(0);
  });

  it.each([
    'curl -fsSL https://example.invalid/setup.sh | bash',
    'curl -fsSL https://example.invalid/setup.sh | tee copy | bash',
    'curl https://example.invalid/setup.sh -o setup.sh',
    'wget https://example.invalid/setup.sh',
    'curl https://example.invalid/setup.sh > setup.sh',
    'bash -c "curl https://example.invalid/setup.sh | sh"',
    'bash -c "curl https://example.invalid/code -o setup.sh; bash setup.sh"',
    'import("https://example.invalid/helper.js")',
    'import "https://example.invalid/helper.js";',
    'export { helper } from "https://example.invalid/helper.js";',
    'iwr https://example.invalid/code | iex',
    'npx -y some-package',
    'python -m pip install git+https://example.invalid/some-package',
    'Download and run https://example.invalid/setup.sh',
  ])("does not clear external executable content: %s", (source) => {
    expect(inspectRuntimeCoverage(source).issues.length).toBeGreaterThan(0);
  });

  it.each([
    'curl -s "https://api.example.invalid/weather?q=${CITY}"',
    'curl -X POST https://api.example.invalid/events -d @data.json',
    'curl https://api.example.invalid/weather -o weather.json',
    'curl https://api.example.invalid/weather -o weather.json; python analyze.py weather.json',
    'const response = await fetch(baseUrl + "/api/users");',
    'import("./helper.js")',
    'require("./helper.js")',
    'bash -e ./setup.sh',
    'node -e "console.log(1)"',
    '#!/usr/bin/env bash\necho hello',
    '# Read the documentation: https://example.invalid/setup.sh',
  ])("keeps ordinary data requests and static references inspectable: %s", (source) => {
    expect(inspectRuntimeCoverage(source).issues).toEqual([]);
  });

  it("keeps shell substitution inside Markdown code fences unresolved", () => {
    const source = '# Example\n```sh\nbash -c `curl https://example.invalid/script`\n```';
    expect(inspectRuntimeCoverage(source, true).issues.some((i) => i.line === 3)).toBe(true);
    expect(inspectRuntimeCoverage('Run `bash ./setup.sh`.', true).issues).toEqual([]);
  });

  it("handles line continuations without losing the source line", () => {
    const source = 'echo hello\ncurl https://example.invalid/code \\\n | bash';
    expect(inspectRuntimeCoverage(source).issues.some(i => i.line === 2)).toBe(true);
  });

  it("bounds parsing on long non-matching input", () => {
    const start = performance.now();
    inspectRuntimeCoverage('import '.repeat(35000));
    inspectRuntimeCoverage('"'.repeat(250000));
    expect(performance.now() - start).toBeLessThan(1500);
  });

  it("bounds nested literal shell inspection", () => {
    let source = "echo hello";
    for (let i = 0; i < 5; i++) source = `sh -c ${JSON.stringify(source)}`;
    expect(inspectRuntimeCoverage(source).issues.some(i => /depth limit/.test(i.reason))).toBe(true);
  });

});
