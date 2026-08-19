<h1 align="center">🛟 Airbag</h1>

<p align="center">
  <b>The airbag for your git push.</b><br>
  Invisible until the moment you would have crashed.
</p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-yellow.svg" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/python-3.8%2B-blue.svg" alt="Python 3.8+">
  <img src="https://img.shields.io/badge/dependencies-0-brightgreen.svg" alt="Zero dependencies">
  <img src="https://img.shields.io/badge/network%20calls-none-blueviolet.svg" alt="No network calls">
</p>

---

Claude Code, Codex, Cursor, Copilot and friends write a lot of code very fast.
They also, very fast, will happily stage your `.env` file, commit `node_modules/`,
leave a merge-conflict marker in a source file, drop an API key into a config
literal, and push the lot without running a single test.

You do not notice any of it — until the day you do, and by then the key is
public and the history is permanent.

Airbag sits between your agent and `git`. It stays completely out of the way
while things are fine, and deploys the instant they are not.

```
$ git commit -m "add stripe integration"

Airbag 0.1.0 | staged changes | 4 file(s) | 0.6s
------------------------------------------------------

BLOCKERS (2) - must be fixed before this change is pushed

  [secrets/stripe-live-key] Stripe live secret key exposed in source
      at src/payments.py:12  sk_l************************dc
      -> Remove the literal from the file and read it from an environment
         variable instead. Treat this credential as compromised: rotate it
         now, then purge it from history if it was ever committed.

  [waste/generated-directory] `node_modules/` should not be in version control
      at node_modules
      This directory holds installed npm dependencies and can be regenerated.
      -> Add `node_modules/` to .gitignore and untrack it with
         `git rm -r --cached node_modules` (files stay on disk).

SUGGESTED FIXES (nothing is applied without your confirmation)
  1. Add 9 pattern(s) to .gitignore
  2. Untrack `node_modules/` (files stay on disk)

RESULT: AIRBAG DEPLOYED - blocked. Resolve the items above before committing or pushing.
        2 blocker(s), 1 warning(s), 2 note(s).

airbag: commit blocked. Fix the items above, or bypass with --no-verify.
```

The commit did not happen.

---

## Why this exists

A secret in a git commit is not like a bug. A bug you fix and move on. A
credential that reaches a remote is **compromised the moment it lands** —
deleting the line in a follow-up commit changes nothing, because the value is
still in the history, in every clone, and in whatever scrapers were watching.
The only real remedy is rotating the key.

The same asymmetry applies to repository weight. A 200 MB file committed once
lives in the history of every clone forever, and shrinking it later means a
force-push that rewrites everyone's branches.

Both mistakes are trivially cheap to prevent and expensive to undo, which makes
the thirty seconds before a commit the single highest-leverage place to check.
Agents are fast enough that no human is reading every diff any more — so the
check has to be automatic, and it has to run **before** the write, not after.

---

## What it checks

| Category | Examples | Default |
|---|---|---|
| **Secrets** | AWS, GitHub, Anthropic, OpenAI, Google, Slack, Stripe, Twilio, SendGrid, npm, PyPI, HuggingFace, Discord, Telegram, DigitalOcean, Shopify, Notion, GitLab, Doppler + 40 more patterns; private key blocks; DB URLs with inline passwords; high-entropy assignments | **block** |
| **Credential files** | `.env`, `.env.local`, `*.pem`, `*.key`, `id_rsa`, `.npmrc`, `credentials.json`, `terraform.tfstate` | **block** |
| **Repo waste** | `node_modules/`, `__pycache__/`, `.venv/`, `.next/`, `.terraform/`, `dist/`, `build/`, compiled binaries, `.DS_Store`, archives, model weights | **block / warn** |
| **File size** | Anything over 50 MB (GitHub's warning line) or 100 MB (GitHub's hard rejection) | **block** |
| **Broken code** | Merge-conflict markers, Python/JSON/TOML/JS files that do not parse | **block** |
| **AI slop** | `// ... rest of the code ...` elisions, `raise NotImplementedError`, "your code here", lorem ipsum | **block / warn** |
| **Debug leftovers** | `debugger;`, `breakpoint()`, `pdb.set_trace()`, `binding.pry`, `console.log` | **block / warn** |
| **Dangerous patterns** | `verify=False`, `rejectUnauthorized: false`, `shell=True`, `eval()`, `pickle.loads`, `innerHTML =`, SQL string building, wildcard CORS, `chmod 777`, `curl \| sh` | **block / warn** |
| **Supply chain** | New dependencies listed for review, `postinstall` hooks, unpinned versions, git/URL dependencies, lockfile drift | **warn / info** |
| **Tests** | Detects your test suite and tells you it has not been run; can run it for you | **warn** |
| **Hygiene** | Missing `.gitignore` entries, pushes straight to `main`, oversized changesets, low-effort commit messages | **warn / info** |

Findings only ever come from **lines you are actually adding**. A pre-existing
`TODO` in a file you happened to touch is not your problem, and Airbag
will not pretend otherwise.

---

## Install

```bash
pip install git+https://github.com/n-bharath-chowdary/airbag
```

> Not on PyPI yet, so install straight from the repository. `pipx install
> git+https://github.com/n-bharath-chowdary/airbag` works too if you
> prefer an isolated install.

Or run it without installing anything — it has no dependencies:

```bash
git clone https://github.com/n-bharath-chowdary/airbag
cd airbag
python -m airbag --help
```

Then, inside the repository you want to protect:

```bash
airbag install          # wires up git hooks + every editor it finds
airbag doctor           # confirm what got installed
```

Install one integration at a time with `airbag install claude`,
`... cursor`, `... codex`, `... windsurf`, `... git`, or `... ci`.

---

## Wiring it into your editor

### Claude Code

```bash
airbag install claude
```

This installs **three** things, and you want all of them — each covers a
different way the check could fail to happen:

1. **The skill** → `.claude/skills/airbag/SKILL.md`
   Teaches Claude the workflow, so it checks *on its own initiative* when you
   say "push this": scan first, explain findings in plain language, ask before
   fixing, never bypass silently.
2. **The `/airbag` command** → `.claude/commands/airbag.md`
   For when *you* want to check, at any moment — not just at push time.
   `/airbag`, `/airbag push`, `/airbag all`, or `/airbag fix`.
3. **A `PreToolUse` hook** → `.claude/settings.json`
   The one that does not rely on cooperation. Every Bash command is inspected;
   if it is a `git commit` or `git push`, the scan runs first no matter what
   the model intended.

| Result | What Claude Code does |
|---|---|
| clean | The command runs. Nothing is printed. |
| warnings | You get a permission prompt listing the warnings, so **you** decide. |
| blockers | The command is refused, and Claude is handed the exact list of what to fix. |

To get the skill and `/airbag` in **every** project instead of one repo, copy
them into your user directories once:

```bash
cp -r skills/airbag   ~/.claude/skills/
cp    commands/airbag.md ~/.claude/commands/
```

The hook still has to be installed per repository (`airbag install claude`),
since it is the layer that touches that repo's git.

### Cursor / Windsurf

```bash
airbag install cursor     # writes .cursor/rules/airbag.mdc
airbag install windsurf   # writes .windsurf/rules/airbag.md
```

An always-applied rule that tells the agent to run `airbag scan --json`
before any commit or push and how to act on each status.

### Codex, Jules, Amp, and anything else that reads `AGENTS.md`

```bash
airbag install codex       # appends a section to AGENTS.md
```

### Plain git hooks (works with any editor, or none)

```bash
airbag install git         # .git/hooks/pre-commit + pre-push
```

This is the backstop. It fires no matter which tool — or which human — runs the
commit, and it does not depend on a model choosing to cooperate.

### CI

```bash
airbag install ci          # .github/workflows/airbag.yml
```

---

## Using it directly

Inside Claude Code, just type:

```
/airbag              # check what is pending right now
/airbag push         # check everything you are about to push
/airbag all          # audit the whole repository
/airbag fix          # check, then apply the safe fixes you approve
```

From any terminal:

```bash
airbag scan                      # staged changes (default)
airbag scan --stage push         # everything you are about to push
airbag scan --all                # audit the entire repository
airbag scan --range main..HEAD   # a specific commit range
airbag scan --json               # machine-readable, for agents
airbag scan --run-tests          # also execute the detected test suite
airbag scan --strict             # treat warnings as blockers

airbag fix --dry-run             # show what the safe fixes would do
airbag fix                       # apply them
airbag doctor                    # what Airbag sees in this repo
```

**Exit codes:** `0` clean · `1` warnings · `2` blockers · `3` could not run.

---

## What `airbag fix` will and will not touch

It only does two reversible things:

- appends patterns to `.gitignore`
- runs `git rm --cached` on files that should never have been staged —
  **the files stay on your disk**, they are only removed from the index

It will **never** rewrite your source code. In particular it does not try to
auto-remove secrets: the right replacement is a judgement call, the key has to
be rotated either way, and a tool guessing at it does more harm than good.
Airbag tells you exactly what to do and leaves the edit to you.

---

## The JSON contract

This is what agents consume:

```jsonc
{
  "tool": "airbag",
  "version": "0.1.0",
  "status": "blocked",              // clean | warned | blocked | error
  "exit_code": 2,
  "stage": "push",
  "scope": { "mode": "staged", "label": "staged changes", "files": 4 },
  "summary": { "block": 2, "warn": 1, "info": 2 },
  "findings": [
    {
      "check": "secrets",
      "rule": "stripe-live-key",
      "severity": "block",
      "title": "Stripe live secret key exposed in source",
      "path": "src/payments.py",
      "line": 12,
      "location": "src/payments.py:12",
      "evidence": "sk_l************************dc",   // always redacted
      "remediation": "Remove the literal from the file and ..."
    }
  ],
  "fixes": [
    {
      "id": "untrack-dir:node_modules",
      "kind": "untrack",
      "description": "Untrack `node_modules/` (files stay on disk)",
      "commands": ["git rm -r --cached -- node_modules"],
      "safe": true
    }
  ],
  "agent_instructions": "STOP. Do not run `git commit` or `git push` ..."
}
```

Secret values are redacted before they reach the report, so a Airbag
result is safe to paste into a chat window, an issue, or a CI log.

---

## Configuration

Drop a `.airbag.json` in your repo root (`//` comments are allowed).
See [`.airbag.example.json`](.airbag.example.json) for the full set.

```jsonc
{
  "fail_on": "block",
  "checks": {
    "waste":  { "block_file_kb": 51200 },
    "tests":  { "mode": "run", "command": "npm test" },
    "quality": { "todos": false }
  },
  "allow": {
    "paths": ["tests/fixtures/**"],
    "rules": ["console-log"]
  }
}
```

### Silencing a single line

```python
API_KEY = "AKIA..."  # airbag:allow
```

Use this for test fixtures and documentation samples. If you find yourself
reaching for it on real code, that is the tool working.

### Bypassing entirely

```bash
git commit --no-verify           # skip the git hook once
AIRBAG_DISABLE=1 git push   # skip everything once
```

Both are honest escape hatches. The Claude Code hook detects `--no-verify` and
steps aside, and the shipped skill instructs the agent never to add that flag
on its own initiative.

---

## Honest limitations

- **Regex-based secret detection has a floor.** It catches the well-known
  formats and high-entropy assignments. A credential in an unusual format, or
  split across lines, can get through. This reduces risk; it does not eliminate
  it. Pair it with GitHub's push protection and provider-side secret scanning.
- **It only sees what git sees.** Files that are already ignored, or changes
  you have not staged, are outside the default scope.
- **It does not detect "unnecessary code" in general.** It has no opinion on
  whether your agent wrote 200 lines where 20 would do, and it cannot find
  dead functions or redundant abstractions — that is a much harder problem and
  a different tool. What it catches is a specific, enumerable list: leftover
  debug statements, elided code, unimplemented stubs, junk and scratch files.
  Use `/code-review` or a linter for the rest.
- **Test execution is opt-in.** Running a repository's test command executes
  arbitrary code from that repository, so Airbag detects your suite and
  reports that it has not run, but will not run it unless you pass
  `--run-tests` or set `"mode": "run"`.
- **JS syntax checking needs Node** and is skipped for ES modules, where
  `node --check` would report false positives. Python, JSON and TOML are
  checked in-process with no external tooling.
- **It cannot un-leak anything.** If a secret is already in your history, the
  fix is rotation plus a history rewrite. Airbag tells you that; it cannot
  do it for you.

---

## How it works

```
git commit / git push
        |
        v
  +-----------------+     staged diff, index blobs, file sizes
  |  scope resolver | --> (added lines only, so old code is not blamed)
  +-----------------+
        |
        v
  secrets · waste · quality · tests · gitignore · deps · hygiene
        |
        v
  findings -> severity -> exit code 0 / 1 / 2
        |
        +--> text report (humans)
        +--> JSON report + agent_instructions (editors)
        +--> fix plan (gitignore + untrack, nothing else)
```

Pure Python standard library. No network calls — your code is never sent
anywhere. Nothing is uploaded, phoned home, or logged off-machine.

---

## Contributing

New secret patterns are the most useful contribution, and the easiest:
add an entry to `PROVIDER_RULES` in
[`airbag/checks/secrets.py`](airbag/checks/secrets.py) and a case to
`test_secret_patterns_are_detected`. Use a **fabricated** key in the test —
never a real one, even an expired one.

```bash
git clone https://github.com/n-bharath-chowdary/airbag
cd airbag
python -m pytest -q
```

If you change anything in `airbag/templates.py`, run
`python scripts/export_integrations.py` to refresh the browsable copies under
`integrations/` and `skills/`.

Bug reports and false positives are very welcome — a false positive is a bug,
because a tool people mute is a tool that protects nobody.

---

## License

MIT — see [LICENSE](LICENSE). Use it, fork it, ship it inside your own tooling.
