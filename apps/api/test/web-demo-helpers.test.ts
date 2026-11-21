import { describe, expect, it } from "vitest";
import { scanSkill } from "@clawvet/shared";
import { resolveSkillFetchUrls } from "../../../web-demo/src/github-url.js";
import { DEMO_SAMPLES } from "../../../web-demo/src/samples.js";

describe("web-demo URL resolver & samples", () => {
  it("converts GitHub blob, tree, repo root, and Gist URLs to raw HTTPS URLs", () => {
    expect(resolveSkillFetchUrls("https://github.com/acme/tools/blob/main/skills/foo/SKILL.md")).toEqual({
      urls: ["https://raw.githubusercontent.com/acme/tools/main/skills/foo/SKILL.md"],
      skillName: "foo",
    });
    expect(resolveSkillFetchUrls("https://github.com/acme/tools/tree/main/skills/bar")).toEqual({
      urls: ["https://raw.githubusercontent.com/acme/tools/main/skills/bar/SKILL.md"],
      skillName: "bar",
    });
    expect(resolveSkillFetchUrls("https://github.com/acme/my-skill")).toEqual({
      urls: [
        "https://raw.githubusercontent.com/acme/my-skill/main/SKILL.md",
        "https://raw.githubusercontent.com/acme/my-skill/master/SKILL.md",
      ],
      skillName: "my-skill",
    });
    expect(resolveSkillFetchUrls("https://gist.github.com/alice/abcdef123456")).toEqual({
      urls: ["https://gist.githubusercontent.com/alice/abcdef123456/raw"],
      skillName: "abcdef123456",
    });
  });

  it("rejects non-HTTPS and private/local network hosts", () => {
    expect(resolveSkillFetchUrls("http://github.com/acme/foo").error).toBeTruthy();
    expect(resolveSkillFetchUrls("https://localhost:3000/SKILL.md").error).toBeTruthy();
    expect(resolveSkillFetchUrls("https://127.0.0.1/SKILL.md").error).toBeTruthy();
    expect(resolveSkillFetchUrls("https://192.168.1.5/SKILL.md").error).toBeTruthy();
    expect(resolveSkillFetchUrls("not-a-url").error).toBeTruthy();
  });

  it("scans all three demo samples with expected grades, dataflow findings, and capabilities", async () => {
    const clean = await scanSkill(DEMO_SAMPLES[0].content, { skipCache: true });
    expect(clean.riskGrade).toBe("A");
    expect(clean.recommendation).toBe("approve");
    expect(clean.capabilities?.some((c) => c.kind === "network" && c.value === "open-meteo.com")).toBe(true);

    const rugPull = await scanSkill(DEMO_SAMPLES[1].content, { skipCache: true });
    expect(rugPull.riskGrade).toBe("F");
    expect(rugPull.recommendation).toBe("block");
    expect(rugPull.findings.some((f) => f.analysisPass === "dataflow")).toBe(true);
    expect(rugPull.capabilities?.some((c) => c.kind === "secret" && c.value === "~/.ssh")).toBe(true);
    expect(rugPull.capabilities?.some((c) => c.kind === "persistence")).toBe(true);

    const promptOast = await scanSkill(DEMO_SAMPLES[2].content, { skipCache: true });
    expect(["D", "F"]).toContain(promptOast.riskGrade);
    expect(promptOast.findings.some((f) => /oast/i.test(f.title) || f.category === "prompt_injection")).toBe(true);
  });
});
