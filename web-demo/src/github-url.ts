/**
 * Convert a user-pasted GitHub, Gist, or raw HTTPS URL into candidate raw
 * download URLs that support browser CORS fetches. Rejects non-HTTPS and
 * private/loopback targets.
 */
const BLOCKED_HOST = /^(?:localhost|127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|0\.0\.0\.0|\[::1\]|.*\.local|.*\.internal)$/i;

export function resolveSkillFetchUrls(rawInput: string): { urls: string[]; skillName?: string; error?: string } {
  const input = rawInput.trim();
  if (!input) return { urls: [], error: "Paste a GitHub URL or raw SKILL.md URL." };

  let parsed: URL;
  try {
    parsed = new URL(input);
  } catch {
    return { urls: [], error: "Invalid URL. Enter a full https:// URL." };
  }

  if (parsed.protocol !== "https:") {
    return { urls: [], error: "Only https:// URLs are supported." };
  }
  if (BLOCKED_HOST.test(parsed.hostname)) {
    return { urls: [], error: "Private or local network hosts are not allowed." };
  }

  const host = parsed.hostname.toLowerCase();
  const segments = parsed.pathname.split("/").filter(Boolean);

  if (host === "github.com") {
    // https://github.com/owner/repo/blob/branch/path/to/SKILL.md
    if (segments.length >= 5 && segments[2] === "blob") {
      const [owner, repo, , branch, ...rest] = segments;
      const skillName = rest.length >= 2 ? rest[rest.length - 2] : repo;
      return {
        urls: [`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${rest.join("/")}`],
        skillName,
      };
    }
    // https://github.com/owner/repo/tree/branch/path/to/skill
    if (segments.length >= 4 && segments[2] === "tree") {
      const [owner, repo, , branch, ...rest] = segments;
      const basePath = rest.length ? `${rest.join("/")}/SKILL.md` : "SKILL.md";
      const skillName = rest.length ? rest[rest.length - 1] : repo;
      return {
        urls: [`https://raw.githubusercontent.com/${owner}/${repo}/${branch}/${basePath}`],
        skillName,
      };
    }
    // https://github.com/owner/repo
    if (segments.length === 2) {
      const [owner, repo] = segments;
      return {
        urls: [
          `https://raw.githubusercontent.com/${owner}/${repo}/main/SKILL.md`,
          `https://raw.githubusercontent.com/${owner}/${repo}/master/SKILL.md`,
        ],
        skillName: repo,
      };
    }
  }

  if (host === "gist.github.com" && segments.length >= 2) {
    return {
      urls: [`https://gist.githubusercontent.com/${segments[0]}/${segments[1]}/raw`],
      skillName: segments[1],
    };
  }

  const skillName = segments.length >= 2 ? segments[segments.length - 2] : segments[0];
  return { urls: [parsed.toString()], skillName };
}
