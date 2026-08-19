"""End-to-end tests.

Each test builds a throwaway git repository, stages a change, and asserts on
the rules that fire. Running against real git (rather than mocking it) is the
point: the diff parsing and index reads are where the bugs live.

    python -m pytest -q
"""

from __future__ import annotations

import json
import os
import subprocess
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from airbag import gitutil  # noqa: E402
from airbag.checks import secrets  # noqa: E402
from airbag.config import load as load_config  # noqa: E402
from airbag.fixes import apply as apply_fixes, plan as plan_fixes  # noqa: E402
from airbag.scanner import scan  # noqa: E402


# --------------------------------------------------------------------------
# helpers
# --------------------------------------------------------------------------

def make_repo(tmp_path):
    root = str(tmp_path)
    subprocess.run(["git", "init", "-q", "-b", "main", root], check=True)
    subprocess.run(["git", "config", "user.email", "t@example.com"], cwd=root, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=root, check=True)
    subprocess.run(["git", "config", "commit.gpgsign", "false"], cwd=root, check=True)
    return root


def write(root, relative, content):
    path = os.path.join(root, relative)
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "wb") as handle:
        handle.write(content.encode("utf-8") if isinstance(content, str) else content)
    return path


def stage(root):
    subprocess.run(["git", "add", "-A"], cwd=root, check=True)


def run_scan(root, stage_name="commit", **overrides):
    config = load_config(root, None)
    for key, value in overrides.items():
        config.data[key] = value
    scope = gitutil.resolve_scope(root, "staged", None, stage_name)
    return scan(root, config, scope, stage_name)


def rules(report):
    return {finding.rule for finding in report.findings}


# --------------------------------------------------------------------------
# secrets
# --------------------------------------------------------------------------

def fake(prefix, body):
    """Assemble a fabricated credential at run time.

    Every value here is invented and non-functional, but it has to match the
    real provider *shape* or it would not exercise the detector. Splitting the
    literal means the contiguous token never appears in this file, so
    provider-side secret scanners - GitHub push protection, and Airbag
    itself - do not flag the test suite as a leak.
    """
    return prefix + body


SECRET_CASES = [
    ("aws-access-key-id", fake("AKIA", "3F7QZLM2XVBNP9RT")),
    ("github-token", fake("ghp_", "9sKq2ZmW8xLd4TbVn7YcRfHj3PgA1Ee6Uo0i")),
    ("anthropic-api-key", fake("sk-ant-api03-", "9dK2mZq7Lw4TbVn8YcRfHj3PgA1Ee6Uo0iXsQr5Tz")),
    ("slack-token", fake("xoxb-", "2841937465-4827361958-Kd8vNqZ2mLpXtRw7YbGfHj3P")),
    ("stripe-live-key", fake("sk_", "live_4eC39HqLyjWDarjtT1zdp7dc")),
    ("google-api-key", fake("AIza", "SyD3mK9pQ7wXvL2nR8tYbF4hJ6cZ1aE5uOi")),
    ("npm-token", fake("npm_", "8Fq2Zx9WmKp4Lv7Rt3Yb6Nc1Hd5Gj0AeQw3x")),
    ("huggingface-token", fake("hf_", "KpLm4Qw8Zx2Vn7Rt3Yb6Nc1Hd5Gj0AeQs")),
]

AWS_FIXTURE = SECRET_CASES[0][1]


@pytest.mark.parametrize("rule,secret", SECRET_CASES)
def test_secret_patterns_are_detected(tmp_path, rule, secret):
    root = make_repo(tmp_path)
    write(root, "app.py", 'KEY = "{}"\n'.format(secret))
    stage(root)
    assert rule in rules(run_scan(root))


@pytest.mark.parametrize(
    "rule,literal",
    [
        ("private-key-block", "-----BEGIN RSA PRIVATE KEY-----"),
        ("db-url-credentials", 'U = "postgres://user:' + 'Qw8vNs2LpTz' + '@host:5432/db"'),
        ("basic-auth-url", 'U = "https://admin:' + 'Zx4Kq9Lm2Pw' + '@internal.example.com/api"'),
    ],
)
def test_secret_shapes_are_detected(tmp_path, rule, literal):
    root = make_repo(tmp_path)
    write(root, "app.py", literal + "\n")
    stage(root)
    assert rule in rules(run_scan(root))


@pytest.mark.parametrize(
    "line",
    [
        'API_KEY = "your_api_key_here"',
        'API_KEY = os.environ["API_KEY"]',
        'API_KEY = "sk-ant-api03-" + "x" * 30,',
        'TOKEN = "${GITHUB_TOKEN}"',
        'SECRET = "changeme"',
        'PASSWORD = process.env.PASSWORD',
    ],
)
def test_placeholders_do_not_fire(tmp_path, line):
    root = make_repo(tmp_path)
    write(root, "app.py", line + "\n")
    stage(root)
    found = rules(run_scan(root))
    assert not {r for r in found if r.startswith(("aws-", "github-", "anthropic-", "high-entropy"))}


def test_env_file_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".env", "SECRET_TOKEN=abc123\n")
    stage(root)
    assert "env-file-committed" in rules(run_scan(root))


def test_env_example_is_not_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".env.example", "SECRET_TOKEN=\n")
    stage(root)
    assert "env-file-committed" not in rules(run_scan(root))


def test_inline_allow_marker_suppresses(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", 'KEY = "' + AWS_FIXTURE + '"  # airbag:allow\n')
    stage(root)
    assert "aws-access-key-id" not in rules(run_scan(root))


def test_evidence_is_redacted(tmp_path):
    root = make_repo(tmp_path)
    literal = AWS_FIXTURE
    write(root, "app.py", 'KEY = "{}"\n'.format(literal))
    stage(root)
    report = run_scan(root)
    for finding in report.findings:
        if finding.evidence:
            assert literal not in finding.evidence
    assert literal not in json.dumps([f.to_dict() for f in report.findings])


def test_entropy_heuristic(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", 'client_secret = "8Fq2Zx9WmKp4Lv7Rt3Yb6Nc1Hd5Gj0Ae"\n')
    stage(root)
    assert "high-entropy-assignment" in rules(run_scan(root))


def test_shannon_entropy_ordering():
    assert secrets.shannon_entropy("aaaaaaaaaaaaaaaa") < 1.0
    assert secrets.shannon_entropy("8Fq2Zx9WmKp4Lv7Rt3Yb6Nc1Hd5Gj0Ae") > 4.0


# --------------------------------------------------------------------------
# waste
# --------------------------------------------------------------------------

def test_node_modules_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "node_modules/left-pad/index.js", "module.exports = 1\n")
    stage(root)
    assert "generated-directory" in rules(run_scan(root))


def test_ds_store_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".DS_Store", "\x00binary")
    stage(root)
    assert "junk-file" in rules(run_scan(root))


def test_large_file_warns(tmp_path):
    root = make_repo(tmp_path)
    write(root, "big.bin", b"x" * (3 * 1024 * 1024))
    stage(root)
    found = rules(run_scan(root))
    assert "file-large" in found or "junk-file" in found


def test_ordinary_source_file_is_clean(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".gitignore", ".env\n.env.local\n.env.*.local\n*.pem\n*.key\n"
                              ".DS_Store\nThumbs.db\n*.log\n")
    write(root, "app.py", "def add(a, b):\n    return a + b\n")
    write(root, "tests/test_app.py", "def test_add():\n    assert 1 + 1 == 2\n")
    stage(root)
    report = run_scan(root)
    assert report.status == "clean", [f.title for f in report.findings]
    assert report.exit_code == 0


# --------------------------------------------------------------------------
# quality
# --------------------------------------------------------------------------

def test_merge_conflict_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", "x = 1\n<<<<<<< HEAD\ny = 2\n=======\ny = 3\n>>>>>>> other\n")
    stage(root)
    assert "merge-conflict-marker" in rules(run_scan(root))


def test_python_syntax_error_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", "def broken(\n    return 1\n")
    stage(root)
    assert "syntax-error" in rules(run_scan(root))


def test_invalid_json_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "data.json", '{"a": 1,}\n')
    stage(root)
    assert "syntax-error" in rules(run_scan(root))


def test_elided_code_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", "def f():\n    # ... rest of the code remains the same\n    return 1\n")
    stage(root)
    assert "elided-code" in rules(run_scan(root))


def test_debugger_statement_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.js", "function f() {\n  debugger;\n}\n")
    stage(root)
    assert "debugger-statement" in rules(run_scan(root))


def test_tls_verification_disabled_is_blocked(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.py", "import requests\nrequests.get(url, verify=False)\n")
    stage(root)
    assert "tls-verification-disabled" in rules(run_scan(root))


def test_untouched_lines_are_not_blamed(tmp_path):
    """A pre-existing debugger must not fail a later, unrelated commit."""
    root = make_repo(tmp_path)
    write(root, "app.js", "function f() {\n  debugger;\n}\n")
    stage(root)
    subprocess.run(["git", "commit", "-qm", "legacy"], cwd=root, check=True)

    write(root, "app.js", "function f() {\n  debugger;\n}\nconst x = 1;\n")
    stage(root)
    assert "debugger-statement" not in rules(run_scan(root))


# --------------------------------------------------------------------------
# config
# --------------------------------------------------------------------------

def test_allow_rules_disables_a_rule(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".airbag.json", json.dumps({"allow": {"rules": ["junk-file"]}}))
    write(root, ".DS_Store", "junk")
    stage(root)
    assert "junk-file" not in rules(run_scan(root))


def test_allow_paths_drops_findings(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".airbag.json", json.dumps({"allow": {"paths": ["fixtures/**"]}}))
    write(root, "fixtures/sample.py", 'KEY = "' + AWS_FIXTURE + '"\n')
    stage(root)
    assert "aws-access-key-id" not in rules(run_scan(root))


def test_strict_promotes_warnings(tmp_path):
    root = make_repo(tmp_path)
    write(root, "app.js", "console.log(1)\n")
    stage(root)
    assert run_scan(root, fail_on="warn").status == "blocked"


def test_config_accepts_line_comments(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".airbag.json", '// a comment\n{"fail_on": "warn"}\n')
    stage(root)
    assert load_config(root, None).fail_on == "warn"


# --------------------------------------------------------------------------
# fixes
# --------------------------------------------------------------------------

def test_fix_untracks_but_keeps_the_file(tmp_path):
    root = make_repo(tmp_path)
    write(root, "node_modules/left-pad/index.js", "module.exports = 1\n")
    stage(root)
    report = run_scan(root)
    apply_fixes(root, plan_fixes(root, report.findings))

    assert os.path.exists(os.path.join(root, "node_modules/left-pad/index.js"))
    tracked = subprocess.run(
        ["git", "ls-files"], cwd=root, stdout=subprocess.PIPE
    ).stdout.decode()
    assert "node_modules" not in tracked


def test_fix_populates_gitignore(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".env", "TOKEN=abc\n")
    stage(root)
    report = run_scan(root)
    apply_fixes(root, plan_fixes(root, report.findings))
    with open(os.path.join(root, ".gitignore")) as handle:
        assert ".env" in handle.read()


def test_fix_is_idempotent(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".env", "TOKEN=abc\n")
    stage(root)
    for _ in range(2):
        report = run_scan(root)
        apply_fixes(root, plan_fixes(root, report.findings))
    with open(os.path.join(root, ".gitignore")) as handle:
        assert handle.read().count(".env\n") == 1


# --------------------------------------------------------------------------
# reporting contract
# --------------------------------------------------------------------------

def test_json_contract(tmp_path):
    from airbag.report import render_json

    root = make_repo(tmp_path)
    write(root, "app.py", 'KEY = "' + AWS_FIXTURE + '"\n')
    stage(root)
    report = run_scan(root)
    payload = json.loads(render_json(report, plan_fixes(root, report.findings)))

    for key in ("tool", "version", "status", "exit_code", "summary", "findings",
                "fixes", "agent_instructions"):
        assert key in payload
    assert payload["status"] == "blocked"
    assert payload["exit_code"] == 2
    for finding in payload["findings"]:
        assert finding["severity"] in ("block", "warn", "info")
        assert finding["remediation"]


def test_exit_codes(tmp_path):
    root = make_repo(tmp_path)
    write(root, ".gitignore", ".env\n.env.local\n.env.*.local\n*.pem\n*.key\n"
                              ".DS_Store\nThumbs.db\n*.log\n")
    write(root, "ok.py", "x = 1\n")
    stage(root)
    assert run_scan(root).exit_code == 0

    write(root, "warn.js", "console.log(1)\n")
    stage(root)
    assert run_scan(root).exit_code == 1

    write(root, "block.py", 'K = "' + AWS_FIXTURE + '"\n')
    stage(root)
    assert run_scan(root).exit_code == 2


def test_a_crashing_check_does_not_take_down_the_scan(tmp_path, monkeypatch):
    from airbag.checks import waste

    root = make_repo(tmp_path)
    write(root, "app.py", "x = 1\n")
    stage(root)

    def boom(ctx):
        raise RuntimeError("synthetic failure")

    monkeypatch.setattr(waste, "run", boom)
    report = run_scan(root)
    assert "check-crashed" in rules(report)
    assert report.exit_code in (0, 1)


def test_hook_command_detection():
    from airbag.hooks import git_subcommands, is_git_write

    assert is_git_write("git push origin main")
    assert is_git_write("git commit -m 'x'")
    assert is_git_write("git -C /tmp/x push")            # global flag with a value
    assert is_git_write("git -c user.name=x commit -m y")
    assert is_git_write("cd /tmp && git push")           # compound command
    assert is_git_write("/usr/bin/git push")             # absolute path
    assert is_git_write("git add . && git commit -m x && git push")

    assert not is_git_write("git status")
    assert not is_git_write("git log --oneline")
    assert not is_git_write("npm run build")
    assert not is_git_write("echo 'git push' > notes.txt")

    assert git_subcommands("git add . && git push") == ["add", "push"]
