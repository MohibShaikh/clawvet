import type { SourceFile } from "../types.js";

export interface PinnedDependency {
  ecosystem: "PyPI" | "npm";
  name: string;
  version: string;
  path: string;
  line: number;
}

const pythonVersion = /^(?:v)?(?:\d+!)?\d+(?:\.\d+)*(?:[-_.]?(?:a|b|c|rc|alpha|beta|pre|preview)[-_.]?\d*)?(?:(?:-\d+|[-_.]?(?:post|rev|r)[-_.]?\d*))?(?:[-_.]?dev[-_.]?\d*)?(?:\+[a-z0-9]+(?:[-_.][a-z0-9]+)*)?$/i;
const npmVersion = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
const pythonPin = /^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]+\])?\s*==\s*([A-Za-z0-9][A-Za-z0-9.!+_-]*)(?=\s|;|$)/;
const record = (v: unknown): v is Record<string, unknown> => !!v && typeof v === "object" && !Array.isArray(v);

// This deliberately reads only literal strings, arrays and the relevant tables.
function toml(text: string): Array<{ section: string; key: string; value: string; offset: number }> {
  const result: Array<{ section: string; key: string; value: string; offset: number }> = [];
  const lines = text.split("\n");
  let section = "";
  for (let i = 0; i < lines.length; i++) {
    let line = lines[i].replace(/("(?:[^"\\]|\\.)*"|'[^']*')|#.*$/g, (m, s) => s ?? "").trim();
    if (!line) continue;
    if (/^\[\[?[^\]]+\]\]?$/.test(line)) { section = line; continue; }
    const match = /^([\w.-]+|"[^"]+"|'[^']+')\s*=\s*(.*)$/.exec(line);
    if (!match) throw new Error("Malformed TOML");
    const offset = i;
    let value = match[2];
    if (value.startsWith("[")) {
      while (!value.trimEnd().endsWith("]") && ++i < lines.length) value += "\n" + lines[i].replace(/("(?:[^"\\]|\\.)*"|'[^']*')|#.*$/g, (m, s) => s ?? "");
      if (!value.trimEnd().endsWith("]")) throw new Error("Malformed TOML array");
    }
    if ((value.startsWith('"') && !/^"(?:[^"\\]|\\.)*"$/.test(value)) || (value.startsWith("'") && !/^'[^']*'$/.test(value))) throw new Error("Malformed TOML string");
    result.push({ section, key: match[1].replace(/^["']|["']$/g, ""), value, offset });
  }
  return result;
}
const literal = (value: string): string | undefined => {
  if (/^'[^']*'$/.test(value)) return value.slice(1, -1);
  if (/^"(?:[^"\\]|\\.)*"$/.test(value)) return JSON.parse(value);
  return undefined;
};

export function extractPinnedDependencies(sources: SourceFile[]): PinnedDependency[] {
  const result: PinnedDependency[] = [];
  const seen = new Set<string>();
  for (const source of sources) {
    if (result.length >= 2000) break;
    const local: PinnedDependency[] = [];
    const add = (ecosystem: "PyPI" | "npm", name: string, version: unknown, offset: number) => {
      if (typeof version !== "string" || !(ecosystem === "npm" ? npmVersion : pythonVersion).test(version)) return;
      if (!(ecosystem === "npm" ? /^(?:@[\w.-]+\/)?[\w.-]+$/ : /^[A-Za-z0-9][A-Za-z0-9._-]*$/).test(name)) return;
      name = name.toLowerCase();
      if (ecosystem === "PyPI") name = name.replace(/[-_.]+/g, "-");
      local.push({ ecosystem, name, version, path: source.path, line: source.startLine + offset });
    };
    const pin = (text: string, offset: number) => { const m = pythonPin.exec(text.trim()); if (m) add("PyPI", m[1], m[2], offset); };
    const name = source.path.split(/[\\/]/).pop() ?? "";
    const lines = source.text.split("\n");
    const locations = new Map<string, number[]>();
    if (["package.json", "package-lock.json", "Pipfile.lock"].includes(name)) lines.forEach((line, i) => {
      for (const match of line.matchAll(/"(?:[^"\\]|\\.)*"(?=\s*:)/g)) {
        try {
          const key = JSON.parse(match[0]) as string;
          const entries = locations.get(key);
          if (entries) entries.push(i); else locations.set(key, [i]);
        } catch { /* JSON validation below handles invalid strings. */ }
      }
    });
    const location = (key: string, value: string) => {
      const entries = locations.get(key) ?? [];
      return entries.find((i) => lines[i].includes(JSON.stringify(value))) ?? entries[0] ?? 0;
    };
    try {
      if (/^(?:requirements|constraints).*\.txt$/i.test(name)) {
        lines.forEach((line, i) => pin(line.replace(/\s+#.*$/, ""), i));
      } else if (["package.json", "package-lock.json", "Pipfile.lock"].includes(name)) {
        const data: unknown = JSON.parse(source.text);
        if (!record(data)) continue;
        if (name === "package.json") {
          for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
            const entries = data[group];
            if (record(entries)) for (const [pkg, version] of Object.entries(entries)) add("npm", pkg, version, location(pkg, String(version)));
          }
        } else if (name === "package-lock.json" && (data.lockfileVersion === 2 || data.lockfileVersion === 3) && record(data.packages)) {
          for (const [path, entry] of Object.entries(data.packages)) {
            if (!path || !record(entry) || entry.link === true) continue;
            const pkg = path.split("node_modules/").pop()!;
            if (pkg === path) continue;
            const start = location(path, "");
            let offset = start;
            for (let i = start; i < lines.length; i++) { if (/"version"\s*:/.test(lines[i])) { offset = i; break; } if (i > start && /}\s*,?\s*$/.test(lines[i])) break; }
            add("npm", typeof entry.name === "string" ? entry.name : pkg, entry.version, offset);
          }
        } else if (name === "Pipfile.lock") {
          for (const group of ["default", "develop"]) if (record(data[group])) {
            for (const [pkg, entry] of Object.entries(data[group])) if (record(entry) && typeof entry.version === "string") pin(`${pkg}${entry.version}`, location(pkg, entry.version));
          }
        }
      } else if (name === "pyproject.toml" || name === "poetry.lock") {
        const entries = toml(source.text);
        if (name === "poetry.lock") {
          let pkg: string | undefined;
          for (const entry of entries) {
            if (entry.section !== "[[package]]") continue;
            if (entry.key === "name") pkg = literal(entry.value);
            if (entry.key === "version" && pkg) { add("PyPI", pkg, literal(entry.value), entry.offset); pkg = undefined; }
          }
        } else for (const entry of entries) {
          if (entry.section === "[project]" && entry.key === "dependencies") {
            if (!entry.value.startsWith("[")) throw new Error("Malformed dependencies");
            const body = entry.value.slice(1, entry.value.lastIndexOf("]"));
            const strings = /"(?:[^"\\]|\\.)*"|'[^']*'/g;
            let m: RegExpExecArray | null;
            while ((m = strings.exec(body))) pin(literal(m[0])!, entry.offset + (body.slice(0, m.index).match(/\n/g)?.length ?? 0));
            if (body.replace(strings, "").replace(/[\s,]/g, "")) throw new Error("Malformed dependencies");
          }
          if (entry.section === "[tool.poetry.dependencies]" && entry.key !== "python") {
            const value = literal(entry.value) ?? literal(/\bversion\s*=\s*("[^"]*"|'[^']*')/.exec(entry.value)?.[1] ?? "");
            if (value) pin(`${entry.key}==${value.replace(/^==/, "")}`, entry.offset);
          }
        }
      } else if (source.language !== "config") {
        // Markdown counts: an agent runs an inline `pip install x==1.2` as readily
        // as one in a fence or a script.
        lines.forEach((line, i) => {
          for (const command of line.matchAll(/\b(?:(?:python[\d.]*\s+-m\s+)?pip3?\s+install|npm\s+(?:i|install))\s+([^\n;&|]+)/g)) {
            const npm = command[0].startsWith("npm");
            for (const token of command[1].match(/(?:"[^"\n]*"|'[^'\n]*'|[^\s]+)/g) ?? []) {
              const text = token.replace(/^["']|["']$/g, "");
              if (npm) { const m = /^((?:@[^/]+\/)?[^@]+)@(.+)$/.exec(text); if (m) add("npm", m[1], m[2], i); }
              else pin(text, i);
            }
          }
        });
      }
    } catch { continue; }
    for (const dep of local) {
      const key = JSON.stringify([dep.ecosystem, dep.name, dep.version]);
      if (!seen.has(key)) { seen.add(key); result.push(dep); }
      if (result.length >= 2000) break;
    }
  }
  return result;
}
