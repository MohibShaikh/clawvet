# Packing fixtures

Inert self-extracting skills: the shape SkillCloak's packing gives a payload
(Ji et al., arXiv 2607.02357), where the staged skill carries only an encoded,
compressed, masked, or archived blob and a loader that restores and runs it
at first use. SkillCloak's own samples are not public, so these follow its
description. They test whether the gate refuses what it cannot read, not the
attack tool.

Every payload decodes to `echo placeholder`. The six controls decode data the
same ways but never execute it. Nothing here is run; the gate only reads.

```bash
node make-fixtures.mjs /tmp/packing > /tmp/packing-dirs.txt
while read d; do ../gate-eval/run-gate.sh <clawvet>/dist/index.js "$d"; done < /tmp/packing-dirs.txt
```

## Results

`results-0.13.2.tsv`, from `clawvet@0.13.2` on npm:

| | Block | Warn | Allow |
|---|---|---|---|
| Packed (12) | 9 | 1 | 2 |
| Controls (6) | 1 | 0 | 5 |

The warn is a base64 pipe written directly in `SKILL.md`. The two packed
skills allowed are a module name built by string concatenation
(`require("chi" + "ld_" + ...)`) and a skill that tells the agent to follow a
guide its own script writes. The control blocked is a tarball of templates:
binary content is never inspected.
