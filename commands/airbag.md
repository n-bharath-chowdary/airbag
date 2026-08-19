---
description: Check the pending change for secrets, waste and broken code before committing or pushing
argument-hint: "[fix | all | push]"
---

Run Airbag against this repository and report back to me.

Pick the invocation based on `$ARGUMENTS`:

- empty       -> `airbag scan --stage commit --json`
- `push`      -> `airbag scan --stage push --json`
- `all`       -> `airbag scan --all --json`  (audit every tracked file)
- `fix`       -> `airbag scan --stage push --json` first, then apply fixes
                 **only after I approve them**

If the `airbag` command is not found, use `python -m airbag ...`, and if that
fails too, `python .airbag/hook.py ...`.

Then:

1. Tell me the status in one line: how many blockers, warnings and notes.
2. For each blocker and warning, in plain language: what it is, which file and
   line, and why it matters here. Do not just paste the JSON at me.
3. List the proposed fixes from the `fixes` array and say what each one would
   change. Be explicit that untracking keeps the file on disk.
4. **Ask me what to do.** Per finding if there are only a few, or grouped if
   there are many: keep it, fix it, or ignore it permanently (which means
   adding it to `allow` in `.airbag.json`, or an `# airbag:allow` comment on
   that line).
5. Apply only what I approve, using `airbag fix` for the listed fixes. Never
   edit my source to remove a secret without showing me the change first.
6. Re-run the scan and tell me the new status.

If a credential was found, tell me plainly that it has to be **rotated at the
provider** - deleting the line does not un-leak it - and check whether it is
already in a previous commit (`git log -S` on the value's prefix), because that
means the history needs rewriting too.

Do not run `git commit` or `git push` as part of this command unless I ask.
