# OpenClaw drifts

ClawVet was written against a documented idea of OpenClaw. Running the real
`openclaw@2026.8.2` against the shipped gadget surfaces where that idea and
the binary disagree. This file is the delta, verified by hand on 2026-09-02.

## The gate contract is right, the on-ramp is not

`clawvet gate` works. It reads install metadata on stdin, writes one JSON
verdict to stdout, and OpenClaw 2026.8.2 honors it. A hostile skill installs
attempt, the gate grades it F, OpenClaw fails closed and writes nothing.
That path is the product and it holds.

Everything around it that is supposed to make it turn-key is unchecked against
the real binary.

## `--print-config` is not copy-paste ready

`clawvet gate --print-config` prints:

```json
{
  "security": {
    "installPolicy": {
      "enabled": true,
      "targets": ["skill"],
      "exec": {
        "command": "/path/node",
        "args": ["/path/clawvet/dist/index.js", "gate"],
        "timeoutMs": 10000
      }
    }
  }
}
```

Real OpenClaw rejects this: `openclaw config validate` fails because
`security.installPolicy.exec.source` is required and must equal `"exec"`.
`--print-config` never emits it. The documented flow is paste, save, done;
the actual flow is paste, splice in `"source": "exec"`, save, done. That
splice is undocumented.

The block also hardcodes absolute paths to `node` and to a `dist/index.js`
that npm lays down under the prefix. Fine on one machine. A moved node or a
different package manager and the block points dead.

## Permissions trap the docs never mention

OpenClaw validates the policy command before running it. It requires the
executable, its argument script, and every parent directory up to the root to
be non-group- and non-world-writable. A stock npm global install is `0755`.

Result: the documented gadget fails with

    install policy failed closed: security.installPolicy.exec.command
    parent directory permissions are too open

until someone runs `chmod 0700` down the whole tree. Nothing tells them. On
machines where the real `node` lives under a group-writable path like
`~/.local/share/fnm/node-versions`, the same check trips on an ancestor
directory nobody thinks belongs to the policy. That one is worth a line in
the docs because the failure message points at npm's tree, not the real
culprit, and launcher-picked node binaries are exactly how most people run
openclaw.

## The gate runs through `args[0]` as a policy script

OpenClaw treats `exec.args[0]` as the policy interpreter command, not as a
plain argument. It does the same regular-file and ownership/perms validation
on it as on `command`, and it surfaces perms errors as
`exec.args[0] ... permissions are too open`. The functional submitter in
`packages/shared` and the `gate` command assume the JSON verdict path; nothing
in ClawVet documents that the args are themselves audited.

## `openclaw policy check` is the wrong second command

The tape runs `openclaw policy check` to prove the config wired. Real
behavior: `policy` is a bundled plugin, disabled by default, and
`policy check` audits a `policy.jsonc` artifact for workspace conformance. On
a fresh config there is no such artifact, so the command reports it missing. It
says nothing about whether the `installPolicy` block is present or valid.

The command that proves the wiring is `openclaw config validate`, which passes
clean for the pasted block. The tape shows the wrong proof.

## `skill install` does not exist

`openclaw skill install` (singular) is unknown to the real binary. The
subcommand is `openclaw skills install` (plural). The tape types the singular
form and would fail with an "Did you mean `skills`?" prompt on any recording
machine.

## `skill-ref` is a directory, not a path

`openclaw skills install <path>` accepted a relative fixture path in the
scenario they had in mind. The real command rejects bare relative paths with

    Invalid skill slug: apps/api/test/fixtures/malicious-stealer

because it treats the argument as a slug unless the resolved target is a
directory. Absolute paths work; relative ones do not. Same symptom, different
cause than the singular/plural issue, and it changes what the tape can ask for
when run from the repo root.

## Node version floor the package enforces, ClawVet does not

`openclaw@2026.8.2` requires Node `>=22.22.3 <23 || >=24.15.0 <25 || >=25.9.0`.
It refuses the project's default Node 22.17.1 at install time. Nobody tells
the demo runner this; the failure is npm's own engine warning baked into the
package. `clawvet-gate`'s integration tests run against `tsx` on whatever node
is present, so they never trip on it.

## The skill tells users to install through npx

Root `SKILL.md:63` recommends `npx clawvet gate --print-config`. One-time,
that works, and it is what a reader of the skill actually types. But
`--print-config` embeds the script path it resolved at print time, and under
`npx` that path is `~/.npm/_npx/<hash>/node_modules/clawvet/dist/index.js`.
The npx cache is a cache. A cleanup pass removes that directory, the policy
executable described in the config no longer exists, and every future install
in OpenClaw fails closed with no path forward short of re-pasting.

The fix the reviewer spelled out is right: change the skill instruction to a
global install, then print:

```
npm install -g clawvet
clawvet gate --print-config
```

`npm i -g` lays down a symlink in `bin/`, which OpenClaw rejects for the
policy command, so hand-writing `$(which clawvet)` fails. The point of
`--print-config` is that it realpath-resolves through the symlink to the real
`dist/index.js` and the real `node`. A global install is permanent, so the
embedded paths outlive any cache cycle.

## Empty skill target is allowed through

With `targets: ["skill"]`, an install request that carries no SKILL.md
prodcues an empty scan: the gate's decision at `packages/cli/src/commands/
gate.ts:210` falls through to a zero-risk "approve" and answers `allow`. For a
plugin that is fine, which is why the README says only `"skill"` is listed.
But now the config targets skills exclusively, and a "skill" with no
instruction layer either is not a skill or is a skill that installs its
payload without telling anyone. Review says it should block. At minimum it
warrants a `warn`, because it is exactly the shape of a skill that sneaks code
in behind a SKILL.md that never arrives.

## `--block-at` accepts nonsense

`packages/cli/src/index.ts:74` parses `--block-at <score>` and
`packages/cli/src/commands/gate.ts:153` only checks `Number.isFinite`. A score
of 760 parses fine and makes `riskScore >= blockAt` never true, silently
disabling score-based blocking while the config looks enforced. Negative
values do the opposite, blocking everything. Integer 0-100 is what the flag
documents; nothing validates it.

## Fixes and where they would land

A scan of today's gates and tests showed a few concrete edits if we want the
demo to match reality:

- `packages/cli` `--print-config`: emit `"source": "exec"` in `exec` so the
  output validates as-is. This is the highest-value single change.
- `SKILL.md` + `packages/cli/README.md`: replace the `npx clawvet gate
  --print-config` instruction with `npm install -g clawvet` followed by
  `clawvet gate --print-config`.
- `packages/cli/src/index.ts`: validate `--block-at` as an integer in 0-100
  and reject anything else at parse time.
- `packages/cli/src/commands/gate.ts`: decide on a missing-SKILL.md skill
  target once, do not let the empty scan fall through to `allow`.
- `gate.ts` / the schema: either document that `args[0]` is audited as a
  policy command, or restructure so the policy runs through `command` with no
  audited argument script.
- `demo/gate.tape`: `policy check` becomes `config validate` (or the policy
  plugin is enabled first, and the policy.jsonc artifact is authored); `skill
  install` becomes `skills install`; the fixture path becomes absolute.
- The security/install-time enforcement docs: add the earlier-break-faced
  cooperate steps of chmod-ing the prefix, and the permissions-trap note.
- `README.md` install-time section: paste a view of the output that says
  paste-and-splice, not paste-and-save, and warns that a relative path is a
  slug, not a filesystem path.

None of these change the verdict contract, the 76/26 thresholds, the scoring,
or the fact that the gate fires unprompted. They are all in the demo and the
docs catching up to the binary that ships.

Status 2026-09-02: every fix in "Fixes and where they would land" landed. The
print-config block now validates as-is, the skill and READMEs recommend a
global install over npx, `--block-at` is range-checked, a skill target with no
SKILL.md blocks, and the demo tape runs against the real `openclaw skills
install` and `openclaw config validate`.