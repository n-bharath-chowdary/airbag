# Claude Code integration

Airbag registers a PreToolUse hook on the Bash tool. Before Claude Code
runs `git commit` or `git push`, the hook scans the change:

  clean    -> the command runs, nothing is printed
  warnings -> Claude is asked to confirm with you before continuing
  blockers -> the command is refused and Claude is told exactly what to fix

Install both the skill and the hook with:

```bash
airbag install claude
```

That writes `.claude/skills/airbag/SKILL.md` and registers the
PreToolUse hook in `.claude/settings.json`.
