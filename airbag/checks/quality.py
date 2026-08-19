"""Code-quality gate aimed at the failure modes of machine-written code.

Everything here runs against *added* lines only, so an old TODO in a file you
happened to touch will not be blamed on you. The categories are:

  syntax       - the file does not parse at all (hard block)
  conflict     - unresolved merge conflict markers (hard block)
  placeholders - elided code, unimplemented stubs, "your code here" (hard block
                 for elisions, warn for stubs)
  debug        - debugger statements and console noise left behind
  dangerous    - eval, shell=True, disabled TLS verification, and friends
  todos        - informational count of new TODO/FIXME markers
"""

from __future__ import annotations

import json
import os
import posixpath
import re
import tempfile
from typing import Dict, List, Optional, Tuple

from ..findings import BLOCK, INFO, WARN, Finding
from ..gitutil import run as run_cmd

MAX_PER_RULE = 8

CODE_EXTENSIONS = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".go", ".rs", ".java",
    ".kt", ".rb", ".php", ".c", ".h", ".cpp", ".hpp", ".cs", ".swift", ".scala",
    ".sh", ".bash", ".zsh", ".ps1", ".sql", ".vue", ".svelte", ".dart", ".ex", ".exs",
}

TEXT_DOC_EXTENSIONS = {".md", ".mdx", ".rst", ".txt", ".adoc"}

# JSON files where `//` comments are conventional and valid in practice.
JSONC_NAMES = {
    "tsconfig.json", "jsconfig.json", "devcontainer.json", "launch.json",
    "settings.json", "keybindings.json", "extensions.json", "tasks.json",
    ".eslintrc.json", ".babelrc.json", ".airbag.json",
}
JSONC_PREFIXES = ("tsconfig.", "jsconfig.", ".airbag.")

# --------------------------------------------------------------------------
# line rules: (rule_id, severity, title, regex, extensions or None, remediation)
# --------------------------------------------------------------------------

LineRule = Tuple[str, str, str, re.Pattern, Optional[set], str]


def _lr(rule_id, severity, title, pattern, extensions, remediation, flags=0) -> LineRule:
    return (rule_id, severity, title, re.compile(pattern, flags), extensions, remediation)


JS = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".vue", ".svelte"}
PY = {".py"}

PLACEHOLDER_RULES: List[LineRule] = [
    _lr("elided-code", BLOCK, "Code was replaced by an elision comment",
        r"^\s*(?://|#|/\*|<!--|--)\s*\.{3}\s*(?:rest of|existing|remaining|previous|unchanged|"
        r"the rest|other|same as|keep)\b.*",
        None,
        "An AI edit replaced real code with a placeholder comment. Restore the omitted code "
        "before committing - this file is almost certainly broken.",
        re.IGNORECASE),
    _lr("elided-code", BLOCK, "Code was replaced by an elision comment",
        r"^\s*(?://|#)\s*\[?\s*\.\.\.\s*\]?\s*$",
        None,
        "A bare `...` comment usually means code was omitted by a generator. Restore it.",
        0),
    _lr("unimplemented-stub", WARN, "Unimplemented stub left in the change",
        r"(?:raise\s+NotImplementedError|throw\s+new\s+Error\(\s*[\"'](?:not\s+implemented|todo)|"
        r"panic\(\s*[\"'](?:not\s+implemented|TODO)|NotImplementedException|"  # airbag:allow
        r"//\s*(?:your|the)\s+(?:code|implementation)\s+(?:goes\s+)?here|"
        r"#\s*(?:your|the)\s+(?:code|implementation)\s+(?:goes\s+)?here|"
        r"//\s*implement(?:ation)?\s+(?:me|this|goes here)\b)",
        None,
        "Implement the function or remove the stub. Shipping a stub that throws at runtime is "
        "worse than not shipping it.",
        re.IGNORECASE),
    _lr("lorem-ipsum", WARN, "Placeholder copy left in the change",
        r"\blorem\s+ipsum\b", None,
        "Replace the placeholder text with real content.",
        re.IGNORECASE),
]

DEBUG_RULES: List[LineRule] = [
    _lr("debugger-statement", BLOCK, "`debugger` statement left in code",
        r"(?:^|[\s;{])debugger\s*;?\s*$", JS,
        "Remove the `debugger` statement - it halts execution in any browser with devtools open."),
    _lr("python-breakpoint", BLOCK, "Python breakpoint left in code",
        r"(?:^|\s)(?:breakpoint\(\)|pdb\.set_trace\(\)|import\s+pdb\b|ipdb\.set_trace\(\))", PY,
        "Remove the breakpoint - it will hang the process in production."),
    _lr("ruby-debugger", BLOCK, "Ruby debugger left in code",
        r"(?:binding\.pry|byebug|binding\.irb)", {".rb", ".erb", ".rake"},
        "Remove the debugger statement."),
    _lr("console-log", WARN, "`console.log` left in code",
        r"console\.(?:log|debug|dir|trace)\s*\(", JS,
        "Remove the console call or replace it with the project logger."),
    _lr("php-dump", WARN, "PHP debug dump left in code",
        r"(?:var_dump\s*\(|dd\s*\(|dump\s*\(|print_r\s*\()", {".php"},
        "Remove the debug dump."),
]

DANGEROUS_RULES: List[LineRule] = [
    _lr("tls-verification-disabled", BLOCK, "TLS certificate verification disabled",
        r"(?:verify\s*=\s*False|rejectUnauthorized\s*:\s*false|"
        r"NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*[\"']?0|"
        r"InsecureSkipVerify\s*:\s*true|CURLOPT_SSL_VERIFYPEER\s*,\s*(?:false|0))",
        None,
        "Never disable certificate verification in committed code - it silently defeats HTTPS. "
        "Use a proper CA bundle instead."),
    _lr("destructive-shell", BLOCK, "Destructive shell command in code",
        r"rm\s+-[rRf]{1,2}[a-zA-Z]*\s+(?:/|\$\{?\w*\}?/?\s*$|~\s*$|\*\s*$)", None,
        "This can wipe a developer's machine or a production volume. Scope the path explicitly."),
    _lr("shell-injection-risk", WARN, "Shell execution with `shell=True`",
        r"subprocess\.(?:run|call|check_output|Popen|check_call)\([^)]*shell\s*=\s*True", PY,
        "Pass an argument list instead of `shell=True` to avoid command injection."),
    _lr("os-system", WARN, "`os.system` call",
        r"\bos\.system\s*\(", PY,
        "Use `subprocess.run([...])` - `os.system` interpolates straight into a shell."),
    _lr("eval-usage", WARN, "`eval` on dynamic input",
        r"(?:^|[^\w.])eval\s*\(", None,
        "Avoid `eval`. Parse the value explicitly (JSON.parse / ast.literal_eval)."),
    _lr("unsafe-deserialization", WARN, "Unsafe deserialization",
        r"(?:pickle\.loads?\s*\(|yaml\.load\s*\((?![^)]*Safe)|marshal\.loads?\s*\()", PY,
        "Use `yaml.safe_load` / a JSON format. Pickle executes arbitrary code on load."),
    _lr("dom-xss-risk", WARN, "Raw HTML injection",
        r"(?:\.innerHTML\s*=|dangerouslySetInnerHTML|\.outerHTML\s*=|document\.write\s*\()", JS,
        "Set text content or sanitise the HTML - this is the classic XSS sink."),
    _lr("sql-string-building", WARN, "SQL built by string concatenation",
        r"(?i)(?:execute|query|raw)\s*\(\s*[f]?[\"'].*(?:SELECT|INSERT|UPDATE|DELETE).*"
        r"(?:[\"']\s*\+|\{|%s\s*[\"']\s*%|\$\{)",
        None,
        "Use parameterised queries - string building here is a SQL injection."),
    _lr("wildcard-cors", WARN, "Wildcard CORS origin",
        r"(?i)access-control-allow-origin[\"']?\s*[:,]\s*[\"']\*[\"']", None,
        "Pin the allowed origins. `*` combined with credentials is rejected by browsers anyway."),
    _lr("django-debug-true", WARN, "`DEBUG = True` committed",
        r"^\s*DEBUG\s*=\s*True", PY,
        "Read DEBUG from the environment. Debug mode leaks stack traces and settings."),
    _lr("curl-pipe-shell", WARN, "`curl | sh` in a script",
        r"curl[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|)sh", {".sh", ".bash", ".zsh", ".yml", ".yaml"},
        "Download, checksum, then execute. Piping to a shell runs whatever the server returns."),
    _lr("chmod-777", WARN, "World-writable permissions",
        r"chmod\s+(?:-R\s+)?0?777", None,
        "Grant the narrowest permissions that work."),
    _lr("swallowed-exception", WARN, "Exception silently swallowed",
        r"(?:except\s*:\s*(?:pass|$)|except\s+\w+(?:\s+as\s+\w+)?\s*:\s*pass\s*$|"
        r"catch\s*\([^)]*\)\s*\{\s*\}\s*$)",
        None,
        "Log the exception or handle it. A silent `pass` hides the bug that caused it."),
]

TODO_RULE = re.compile(r"(?:^|[^\w])(TODO|FIXME|XXX|HACK)\b[:\s]", re.IGNORECASE)
CONFLICT_START = re.compile(r"^(?:<{7}|>{7})(?:\s|$)")


def _ext(path: str) -> str:
    return posixpath.splitext(path.replace("\\", "/").lower())[1]


def run(ctx) -> List[Finding]:
    cfg = ctx.config
    findings: List[Finding] = []
    counts: Dict[str, int] = {}
    todo_hits: List[Tuple[str, int]] = []
    conflicted: set = set()

    rule_sets: List[LineRule] = []
    if cfg.opt("quality", "placeholders", True):
        rule_sets += PLACEHOLDER_RULES
    if cfg.opt("quality", "debug_statements", True):
        rule_sets += DEBUG_RULES
    if cfg.opt("quality", "dangerous", True):
        rule_sets += DANGEROUS_RULES

    for path, lines in ctx.added.items():
        ext = _ext(path)
        is_doc = ext in TEXT_DOC_EXTENSIONS
        conflict_reported = False

        for lineno, line in lines:
            if ctx.line_ignored(line):
                continue

            if not conflict_reported and CONFLICT_START.match(line):
                conflict_reported = True
                conflicted.add(path)
                findings.append(
                    Finding(
                        check="quality",
                        rule="merge-conflict-marker",
                        severity=BLOCK,
                        title="Unresolved merge conflict in `{}`".format(path),
                        detail="Conflict marker found at line {}.".format(lineno),
                        path=path,
                        line=lineno,
                        evidence=line.strip()[:60],
                        remediation="Resolve the conflict and remove the <<<<<<< / ======= / "
                                    ">>>>>>> markers before committing.",
                    )
                )
                continue

            # Prose describes code, it does not run it. Every line rule here is
            # about executable behaviour, so none of them apply inside docs.
            # (Secret detection is a separate check and still covers docs.)
            if is_doc:
                continue

            for rule_id, severity, title, pattern, extensions, remediation in rule_sets:
                if extensions is not None and ext not in extensions:
                    continue
                if not pattern.search(line):
                    continue
                if _count_ok(counts, rule_id):
                    findings.append(
                        Finding(
                            check="quality",
                            rule=rule_id,
                            severity=severity,
                            title=title,
                            path=path,
                            line=lineno,
                            evidence=line.strip()[:120],
                            remediation=remediation,
                        )
                    )
                break

            if cfg.opt("quality", "todos", True) and ext in CODE_EXTENSIONS:
                if TODO_RULE.search(line):
                    todo_hits.append((path, lineno))

    findings += _truncation_notes(counts)

    if todo_hits:
        sample = ", ".join("{}:{}".format(p, n) for p, n in todo_hits[:3])
        findings.append(
            Finding(
                check="quality",
                rule="todo-added",
                severity=INFO,
                title="{} new TODO/FIXME marker(s) added".format(len(todo_hits)),
                detail="First few: {}.".format(sample),
                path=todo_hits[0][0],
                line=todo_hits[0][1],
                remediation="Fine to keep, but make sure none of them mark unfinished work in "
                            "the code path you are shipping.",
            )
        )

    if cfg.opt("quality", "syntax", True):
        # A file with conflict markers cannot parse; reporting both is just noise.
        findings += _syntax_findings(ctx, skip=conflicted)
    return findings


def _count_ok(counts: Dict[str, int], rule_id: str) -> bool:
    counts[rule_id] = counts.get(rule_id, 0) + 1
    return counts[rule_id] <= MAX_PER_RULE


def _truncation_notes(counts: Dict[str, int]) -> List[Finding]:
    notes = []
    for rule_id, count in counts.items():
        if count > MAX_PER_RULE:
            notes.append(
                Finding(
                    check="quality",
                    rule=rule_id + "-truncated",
                    severity=INFO,
                    title="{} more `{}` hit(s) not listed".format(count - MAX_PER_RULE, rule_id),
                    detail="Output truncated at {} findings per rule.".format(MAX_PER_RULE),
                    remediation="Run `airbag scan --json` for the full list.",
                )
            )
    return notes


# --------------------------------------------------------------------------
# syntax validation
# --------------------------------------------------------------------------

def _syntax_findings(ctx, skip=frozenset()) -> List[Finding]:
    findings: List[Finding] = []
    node_available: Optional[bool] = None

    for path in ctx.files:
        if path in skip:
            continue
        ext = _ext(path)
        if ext not in (".py", ".json", ".js", ".cjs", ".mjs", ".toml"):
            continue
        data = ctx.content(path)
        if data is None or ctx.is_binary(path):
            continue
        try:
            text = data.decode("utf-8")
        except UnicodeDecodeError:
            continue

        if ext == ".py":
            problem = _python_syntax(text, path)
        elif ext == ".json":
            if _is_jsonc(path):
                continue
            problem = _json_syntax(text)
        elif ext == ".toml":
            problem = _toml_syntax(text)
        else:
            if node_available is None:
                node_available = _node_present()
            problem = _js_syntax(path, text) if node_available else None

        if problem is None:
            continue
        message, lineno = problem
        findings.append(
            Finding(
                check="quality",
                rule="syntax-error",
                severity=BLOCK,
                title="`{}` does not parse".format(path),
                detail=message,
                path=path,
                line=lineno,
                remediation="Fix the syntax error. This file cannot run in its current state.",
            )
        )
    return findings


def _is_jsonc(path: str) -> bool:
    base = posixpath.basename(path.replace("\\", "/")).lower()
    return (
        base in JSONC_NAMES
        or base.endswith(".jsonc")
        or base.startswith(JSONC_PREFIXES)
    )


def _node_present() -> bool:
    code, _, _ = run_cmd(["node", "--version"])
    return code == 0


def _python_syntax(text: str, path: str) -> Optional[Tuple[str, Optional[int]]]:
    try:
        compile(text, path, "exec")
    except SyntaxError as exc:
        return ("{}: {}".format(type(exc).__name__, exc.msg), exc.lineno)
    except ValueError as exc:
        return ("ValueError: {}".format(exc), None)
    return None


def _json_syntax(text: str) -> Optional[Tuple[str, Optional[int]]]:
    if not text.strip():
        return None
    try:
        json.loads(text)
    except ValueError as exc:
        lineno = getattr(exc, "lineno", None)
        return ("Invalid JSON: {}".format(exc), lineno)
    return None


def _toml_syntax(text: str) -> Optional[Tuple[str, Optional[int]]]:
    try:
        import tomllib
    except ImportError:
        return None
    try:
        tomllib.loads(text)
    except Exception as exc:  # tomllib raises TOMLDecodeError
        return ("Invalid TOML: {}".format(exc), None)
    return None


_NODE_LINE = re.compile(r":(\d+)\s*$|:(\d+)\n")


def _js_syntax(path: str, text: str) -> Optional[Tuple[str, Optional[int]]]:
    ext = _ext(path)
    is_module = ext == ".mjs" or re.search(r"^\s*(?:import\s|export\s)", text, re.MULTILINE)
    if ext == ".js" and is_module:
        # `node --check` treats .js as CommonJS; ESM syntax would false-positive.
        return None

    suffix = ext if ext in (".js", ".cjs", ".mjs") else ".js"
    handle = tempfile.NamedTemporaryFile("wb", suffix=suffix, delete=False)
    try:
        handle.write(text.encode("utf-8"))
        handle.close()
        code, _, err = run_cmd(["node", "--check", handle.name])
        if code == 0:
            return None
        first = err.strip().splitlines()
        message = next((ln.strip() for ln in first if "Error" in ln), "Syntax error")
        lineno = None
        for line in first:
            match = re.search(r"{}:(\d+)".format(re.escape(os.path.basename(handle.name))), line)
            if match:
                lineno = int(match.group(1))
                break
        return (message[:200], lineno)
    finally:
        try:
            os.unlink(handle.name)
        except OSError:
            pass
