#!/usr/bin/env python
"""Write the integration templates out to `integrations/` and `skills/`.

`airbag/templates.py` is the single source of truth. Run this after
editing it so the browsable copies in the repository stay in sync:

    python scripts/export_integrations.py
"""

from __future__ import annotations

import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from airbag import templates  # noqa: E402


FILES = {
    # The standalone copies assume `airbag` is on PATH, so they have no
    # launcher script to guard.
    "integrations/git-hooks/pre-commit": templates.PRE_COMMIT_HOOK
    .replace("__AIRBAG_PYTHON__", "python")
    .replace("__AIRBAG_SCRIPT__", ""),
    "integrations/git-hooks/pre-push": templates.PRE_PUSH_HOOK
    .replace("__AIRBAG_PYTHON__", "python")
    .replace("__AIRBAG_SCRIPT__", ""),
    "integrations/cursor/airbag.mdc": templates.CURSOR_RULE,
    "integrations/windsurf/airbag.md": templates.CURSOR_RULE,
    "integrations/codex/AGENTS.snippet.md": templates.AGENTS_SECTION,
    "integrations/github-actions/airbag.yml": templates.GITHUB_WORKFLOW,
    "integrations/claude-code/README.md": (
        "# Claude Code integration\n\n"
        + templates.CLAUDE_SETTINGS_NOTE
        + "\nInstall both the skill and the hook with:\n\n"
        + "```bash\nairbag install claude\n```\n\n"
        + "That writes `.claude/skills/airbag/SKILL.md` and registers the\n"
        + "PreToolUse hook in `.claude/settings.json`.\n"
    ),
    "integrations/claude-code/settings.example.json": (
        '{\n'
        '  "hooks": {\n'
        '    "PreToolUse": [\n'
        '      {\n'
        '        "matcher": "Bash",\n'
        '        "hooks": [\n'
        '          {\n'
        '            "type": "command",\n'
        '            "command": "airbag hook claude"\n'
        '          }\n'
        '        ]\n'
        '      }\n'
        '    ]\n'
        '  }\n'
        '}\n'
    ),
    "skills/airbag/SKILL.md": templates.SKILL_MD,
    "commands/airbag.md": templates.SLASH_COMMAND,
    "integrations/claude-code/airbag.command.md": templates.SLASH_COMMAND,
    ".airbag.example.json": templates.CONFIG_EXAMPLE,
}


def main() -> int:
    for relative, content in FILES.items():
        path = os.path.join(ROOT, relative)
        directory = os.path.dirname(path)
        if directory and not os.path.isdir(directory):
            os.makedirs(directory, exist_ok=True)
        with open(path, "wb") as handle:
            handle.write(content.replace("\r\n", "\n").encode("utf-8"))
        print("wrote {}".format(relative))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
