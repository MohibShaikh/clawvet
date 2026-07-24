---
name: release-check
description: Verify a clawvet release is actually consistent across npm, git tags, GitHub Releases, ClawHub, and the Claude plugin marketplace. Use before cutting a release, after publishing, or whenever a version looks stale anywhere.
allowed-tools: [Bash, Read, Edit]
---

# release-check

clawvet ships to five places that drift independently. Verify state; never
infer it from a success screen.

## Run it

```bash
node scripts/release-check.mjs
```

Exit 0 = no hard failures. Exit 1 = at least one FAIL. Report the output as-is
and fix what it flags — do not summarize a FAIL away.

## What each level means

- **FAIL** — a real inconsistency. Fix before claiming the release is done.
- **WARN** — needs a human decision, not automatically wrong. A ClawHub version
  behind npm is expected (see below); a dirty tree before a release is not.
- **ok** — verified against the source of truth, not assumed.

## Where the releases live

| Channel | How it updates | Automated? |
|---------|----------------|------------|
| npm | `v*` tag push → `.github/workflows/release.yml` | yes |
| GitHub Release | same workflow, after the npm publish | yes |
| git tag | `git push origin v<version>` | manual |
| Claude plugin marketplace | pushing to `master` **is** the release | nothing to do |
| ClawHub | web UI only | manual |

## Cutting a release

1. Bump `packages/cli/package.json`, add a `## <version>` entry to `CHANGELOG.md`.
   Update the root `SKILL.md` frontmatter version too — that file is what a
   ClawHub re-import reads.
2. Commit, then `git tag v<version>` and `git push origin master && git push origin v<version>`.
   **The tag push is the trigger** — pushing master alone publishes nothing.
3. Run this check and confirm npm and the GitHub Release both moved.
4. Update ClawHub by hand if the listing matters for this release.

## Known-good oddities — do not "fix" these

- **ClawHub reports a different version than npm.** ClawHub auto-assigns its own
  version number and ignores `SKILL.md` frontmatter entirely. It will never
  track npm exactly. The check reports ClawHub's version; it never asserts equality.
- **`clawvet-guard` must have exactly one tracked `SKILL.md`**, under
  `plugins/clawvet-guard/skills/`. ClawHub matches on slug, not path, so one file
  serves both ClawHub and the Claude marketplace. A second copy silently drifts.

## When a check fails

- *no `## <version>` in CHANGELOG* — the bump was committed without release notes.
- *tag not created / not pushed* — npm can ship a version git has no record of.
  That is how 0.8.0 ended up published with no commit and no tag.
- *no Release for tag* — tags do not update the Releases page. The workflow does
  this now; a failure here means it did not run or was bypassed.
- *ClawHub not publicly reachable* — the listing may be hidden. A listing with no
  SKILL.md content attached means the publish half-failed; check for a moderation
  hold before republishing, and never republish under a new slug to route around one.
