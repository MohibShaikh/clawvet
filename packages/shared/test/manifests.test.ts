import { describe, expect, it } from "vitest";
import { extractPinnedDependencies as extract } from "../src/scanner/manifests.js";
import type { SourceFile } from "../src/types.js";
const source = (path: string, text: string, startLine = 10): SourceFile => ({ path, text, startLine, endLine: startLine + text.split("\n").length - 1, language: path.endsWith(".sh") ? "shell" : "config" });

describe("pinned manifests", () => {
  it("reads requirements and constraints with normalization, markers, extras and hashes", () => {
    const deps = extract([source("requirements-dev.txt", '# comment\nFoo_Bar[baz]==1.2.3 ; python_version > "3" # ok\n-r other.txt\nnope>=1.0\nwild==1.*\nthing==2.0 --hash=sha256:placeholder'), source("constraints.txt", "foo.bar==1.2.3\nOther==3.0")]);
    expect(deps.map((d) => [d.name, d.version, d.line])).toEqual([["foo-bar", "1.2.3", 11], ["thing", "2.0", 15], ["other", "3.0", 11]]);
  });
  it("reads exact package versions across dependency groups", () => {
    const text = '{\n "dependencies": {"FOO":"1.2.3", "range":"^1.2.3", "tag":"latest", "url":"https://example.invalid/x"},\n "devDependencies":{"@Scope/Pkg":"2.0.0-beta.1"},\n "optionalDependencies":{"bar":"3.0.0"}\n}';
    expect(extract([source("package.json", text)]).map((d) => [d.name, d.line])).toEqual([["foo", 11], ["@scope/pkg", 12], ["bar", 13]]);
  });
  it.each([2, 3])("reads package-lock v%s packages, including nested scoped modules", (lockfileVersion) => {
    const deps = extract([source("package-lock.json", JSON.stringify({ lockfileVersion, packages: { "": { name: "root", version: "1.0.0" }, "node_modules/foo": { version: "1.0.0" }, "node_modules/foo/node_modules/@Scope/Bar": { version: "2.0.0" }, "node_modules/link": { link: true, version: "3.0.0" } } }))]);
    expect(deps.map((d) => d.name)).toEqual(["foo", "@scope/bar"]);
  });
  it("reads PEP621 multiline dependencies and Poetry exact pins", () => {
    const text = '[project]\ndependencies = [\n "Foo[extra]==1.2.3; os_name == \'posix\'",\n "range>=2.0",\n]\n[tool.poetry.dependencies]\npython = "^3.10"\nBar = "2.3.0"\nBaz = { version = "3.0", optional = true }\nrange = "^1.0"';
    expect(extract([source("pyproject.toml", text)]).map((d) => [d.name, d.version, d.line])).toEqual([["foo", "1.2.3", 12], ["bar", "2.3.0", 17], ["baz", "3.0", 18]]);
  });
  it("reads Poetry and Pipfile locks", () => {
    expect(extract([source("poetry.lock", '[[package]]\nname = "Foo_Bar"\nversion = "1.2.3"\n[[package]]\nname = "other"\nversion = "2.0"'), source("Pipfile.lock", '{"default":{"Baz":{"version":"==3.0"}},"develop":{"dev":{"version":"==4.0"}}}')]).map((d) => d.name)).toEqual(["foo-bar", "other", "baz", "dev"]);
  });
  it.each([["package.json", "{"], ["Pipfile.lock", "null"], ["package-lock.json", "[]"], ["pyproject.toml", '[project]\ndependencies = ["x==1.0"'], ["poetry.lock", '[[package]]\nname="x"\nversion="1.0"\nbroken']])("rejects malformed %s", (path, text) => {
    expect(extract([source(path, text)])).toEqual([]);
  });
  it("reads inline pip, pip3, python -m pip and scoped npm installs", () => {
    expect(extract([source("setup.sh", 'pip install "Foo==1.2.3" range>=1.0\npip3 install bar==2.0\npython3 -m pip install baz==3.0\nnpm i @Scope/Pkg@1.0.0 nope@latest\nnpm install foo@2.0.0')]).map((d) => [d.name, d.line])).toEqual([["foo", 10], ["bar", 11], ["baz", 12], ["@scope/pkg", 13], ["foo", 14]]);
  });
  it("caps dependencies and keeps first occurrence", () => {
    const deps = extract([source("requirements.txt", Array.from({ length: 2100 }, (_, i) => `pkg${i}==1.0`).join("\n")), source("setup.sh", "pip install pkg0==1.0")]);
    expect(deps).toHaveLength(2000);
    expect(deps[0].path).toBe("requirements.txt");
  });
});

it.skipIf(process.env.CLAWVET_MANIFEST_BENCH !== "1")("measures manifests in a deterministic MalSkillBench sample", async () => {
  const { readdir, readFile } = await import("node:fs/promises");
  const { join } = await import("node:path");
  const { homedir } = await import("node:os");
  const { performance } = await import("node:perf_hooks");
  const root = join(homedir(), "personal-projects/jev-skillbench/data/MalSkillBench/Dataset/Skills");
  const samples: SourceFile[][] = [];
  for (const category of ["benign", "malware"]) {
    const base = join(root, category);
    const skills = (await readdir(base, { withFileTypes: true })).filter((d) => d.isDirectory()).map((d) => d.name).sort().slice(0, 250);
    for (const skill of skills) {
      const directory = join(base, skill);
      const files = await readdir(directory, { recursive: true, withFileTypes: true });
      const sources: SourceFile[] = [];
      for (const file of files) {
        if (!file.isFile() || !/^(?:(?:requirements|constraints).*\.txt|package(?:-lock)?\.json|pyproject\.toml|poetry\.lock|Pipfile\.lock)$/.test(file.name)) continue;
        const path = join(file.parentPath, file.name);
        sources.push(source(path, await readFile(path, "utf8"), 1));
      }
      samples.push(sources);
    }
  }
  expect(samples).toHaveLength(500);
  for (const sources of samples) extract(sources);
  const times: number[] = [];
  const populatedTimes: number[] = [];
  let pinnedSkills = 0;
  for (const sources of samples) {
    const start = performance.now();
    const deps = extract(sources);
    const elapsed = performance.now() - start;
    times.push(elapsed);
    if (sources.length) populatedTimes.push(elapsed);
    if (deps.length) pinnedSkills++;
  }
  const stats = (values: number[]) => {
    values.sort((a, b) => a - b);
    return { medianMs: values[Math.floor(values.length / 2)], p95Ms: values[Math.ceil(values.length * .95) - 1], maxMs: values.at(-1) };
  };
  process.stdout.write(JSON.stringify({ measurement: "measured", selection: "first 250 sorted directories per benign/malware category", skills: samples.length, manifestFiles: samples.reduce((n, s) => n + s.length, 0), skillsWithManifests: populatedTimes.length, pinnedSkills, allSkills: stats(times), skillsWithManifestsOnly: stats(populatedTimes) }) + "\n");
});
