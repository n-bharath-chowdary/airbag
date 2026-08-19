"""Airbag - a pre-commit / pre-push safety gate for AI coding agents.

Airbag inspects what is *about* to enter a git repository and reports
three classes of problem that AI-assisted development produces at scale:

  1. Leaked credentials  - API keys, tokens, private keys, .env files.
  2. Repository waste    - node_modules, build output, huge binaries, junk.
  3. Untested / unsafe   - syntax errors, conflict markers, debug leftovers,
                           unimplemented stubs, dangerous code patterns,
                           and a test suite that was never run.

It is designed to be driven by an agent (Claude Code, Codex, Cursor, ...)
via ``--json``, and by humans via plain text output.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
