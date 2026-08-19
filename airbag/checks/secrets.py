"""Credential and secret detection.

Two complementary strategies:

1. High-confidence provider patterns (``AKIA...``, ``sk-ant-...``, ``ghp_...``).
   These are precise enough to hard-block on.
2. Contextual heuristics - an assignment to a secret-ish name whose value has
   high Shannon entropy. Noisier, so it is skipped in docs/example files and
   filtered aggressively against placeholder values.

Anything reported is redacted before it reaches the output, so a Airbag
report can safely be pasted into a chat window or CI log.
"""

from __future__ import annotations

import fnmatch
import math
import os
import re
from typing import List, Optional, Pattern, Tuple

from ..findings import BLOCK, WARN, Finding, redact

# --------------------------------------------------------------------------
# provider patterns
# --------------------------------------------------------------------------

Rule = Tuple[str, str, str, Pattern[str], int]  # id, label, severity, regex, group


def _r(rule_id: str, label: str, severity: str, pattern: str, group: int = 1) -> Rule:
    return (rule_id, label, severity, re.compile(pattern), group)


PROVIDER_RULES: List[Rule] = [
    _r("private-key-block", "Private key block", BLOCK,
       r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----", 0),
    _r("aws-access-key-id", "AWS access key id", BLOCK,
       r"\b((?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16})\b"),
    _r("aws-secret-access-key", "AWS secret access key", BLOCK,
       r"(?i)aws.{0,24}(?:secret|private).{0,24}[:=]\s*[\"']?([A-Za-z0-9/+=]{40})[\"']?"),
    _r("github-token", "GitHub token", BLOCK,
       r"\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255})\b"),
    _r("github-fine-grained-pat", "GitHub fine-grained PAT", BLOCK,
       r"\b(github_pat_[A-Za-z0-9_]{60,255})\b"),
    _r("gitlab-pat", "GitLab personal access token", BLOCK,
       r"\b(glpat-[A-Za-z0-9_\-]{20,})\b"),
    _r("anthropic-api-key", "Anthropic API key", BLOCK,
       r"\b(sk-ant-(?:api\d{2}-)?[A-Za-z0-9_\-]{24,})\b"),
    _r("openai-api-key", "OpenAI API key", BLOCK,
       r"\b(sk-(?!ant-)(?:proj-|svcacct-|admin-)?[A-Za-z0-9_\-]{24,})\b"),
    _r("google-api-key", "Google API key", BLOCK,
       r"\b(AIza[0-9A-Za-z_\-]{35})\b"),
    _r("google-oauth-secret", "Google OAuth client secret", BLOCK,
       r"\b(GOCSPX-[A-Za-z0-9_\-]{20,})\b"),
    _r("gcp-service-account", "GCP service account key file", BLOCK,
       r"[\"']type[\"']\s*:\s*[\"']service_account[\"']", 0),
    _r("slack-token", "Slack token", BLOCK,
       r"\b(xox[abprs]-[A-Za-z0-9\-]{10,})\b"),
    _r("slack-webhook", "Slack incoming webhook", BLOCK,
       r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+)"),
    _r("stripe-live-key", "Stripe live secret key", BLOCK,
       r"\b((?:sk|rk)_live_[A-Za-z0-9]{16,})\b"),
    _r("stripe-test-key", "Stripe test key", WARN,
       r"\b((?:sk|rk)_test_[A-Za-z0-9]{16,})\b"),
    _r("twilio-api-key", "Twilio API key", BLOCK,
       r"\b(SK[0-9a-fA-F]{32})\b"),
    _r("sendgrid-api-key", "SendGrid API key", BLOCK,
       r"\b(SG\.[A-Za-z0-9_\-]{16,32}\.[A-Za-z0-9_\-]{16,64})\b"),
    _r("mailgun-api-key", "Mailgun API key", BLOCK,
       r"\b(key-[0-9a-f]{32})\b"),
    _r("mailchimp-api-key", "Mailchimp API key", BLOCK,
       r"\b([0-9a-f]{32}-us\d{1,2})\b"),
    _r("npm-token", "npm access token", BLOCK,
       r"\b(npm_[A-Za-z0-9]{36})\b"),
    _r("npmrc-auth-token", "npm _authToken", BLOCK,
       r"_authToken\s*=\s*([^\s\"']{8,})"),
    _r("pypi-token", "PyPI upload token", BLOCK,
       r"\b(pypi-AgEIcHlwaS5vcmc[A-Za-z0-9_\-]{50,})\b"),
    _r("huggingface-token", "Hugging Face token", BLOCK,
       r"\b(hf_[A-Za-z0-9]{30,})\b"),
    _r("replicate-token", "Replicate API token", BLOCK,
       r"\b(r8_[A-Za-z0-9]{37,})\b"),
    _r("groq-api-key", "Groq API key", BLOCK,
       r"\b(gsk_[A-Za-z0-9]{40,})\b"),
    _r("perplexity-api-key", "Perplexity API key", BLOCK,
       r"\b(pplx-[A-Za-z0-9]{32,})\b"),
    _r("xai-api-key", "xAI API key", BLOCK,
       r"\b(xai-[A-Za-z0-9]{32,})\b"),
    _r("discord-bot-token", "Discord bot token", BLOCK,
       r"\b([MNO][A-Za-z\d_\-]{23,25}\.[A-Za-z\d_\-]{6}\.[A-Za-z\d_\-]{27,})\b"),
    _r("telegram-bot-token", "Telegram bot token", BLOCK,
       r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{32,})\b"),
    _r("digitalocean-token", "DigitalOcean token", BLOCK,
       r"\b(dop_v1_[a-f0-9]{64})\b"),
    _r("shopify-token", "Shopify access token", BLOCK,
       r"\b(shp(?:at|ca|pa|ss)_[a-fA-F0-9]{32})\b"),
    _r("square-token", "Square access token", BLOCK,
       r"\b(sq0(?:atp|csp)-[A-Za-z0-9_\-]{22,})\b"),
    _r("notion-token", "Notion integration token", BLOCK,
       r"\b((?:secret_|ntn_)[A-Za-z0-9]{40,})\b"),
    _r("postman-api-key", "Postman API key", BLOCK,
       r"\b(PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34})\b"),
    _r("doppler-token", "Doppler token", BLOCK,
       r"\b(dp\.(?:pt|st|sa|ct)\.[A-Za-z0-9_\-]{40,})\b"),
    _r("linear-api-key", "Linear API key", BLOCK,
       r"\b(lin_api_[A-Za-z0-9]{40,})\b"),
    _r("db-url-credentials", "Database URL with inline password", BLOCK,
       r"\b(?:postgres|postgresql|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqp|amqps|mssql|clickhouse)://"
       r"[^\s:@/\"']+:([^\s:@/\"']{3,})@[^\s\"']+"),
    _r("basic-auth-url", "Credentials embedded in URL", BLOCK,
       r"https?://[^\s:@/\"']{2,}:([^\s:@/\"']{3,})@[^\s\"']+"),
    _r("jwt-token", "JSON Web Token", WARN,
       r"\b(eyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})\b"),
    _r("sentry-dsn", "Sentry DSN with secret", WARN,
       r"(https://[a-f0-9]{32}(?::[a-f0-9]{32})?@[A-Za-z0-9.\-]+/\d+)"),
]

# --------------------------------------------------------------------------
# contextual heuristics
# --------------------------------------------------------------------------

SECRET_NAME = re.compile(
    r"(?i)\b("
    r"api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|secret|token|access[_-]?token|"
    r"auth[_-]?token|refresh[_-]?token|bearer|client[_-]?secret|private[_-]?key|"
    r"encryption[_-]?key|signing[_-]?key|session[_-]?secret|passwd|password|pwd|"
    r"credential|conn(?:ection)?[_-]?string|dsn"
    r")\b"
)

ASSIGNMENT = re.compile(
    r"""(?ix)
    ([A-Za-z_][A-Za-z0-9_\-\.]{2,40})      # key
    \s*(?::=|=>|[:=])\s*                   # separator
    (?P<q>["'`])?                          # optional quote
    (?P<val>[^\s"'`,;)}\]]{8,200})         # value
    (?P=q)?                                # closing quote
    """
)

PLACEHOLDER_TOKENS = (
    "your", "my_", "example", "sample", "placeholder", "changeme", "change_me",
    "dummy", "fake", "test_key", "testkey", "insert", "replace", "todo", "tbd",
    "redacted", "xxxx", "aaaa", "1234", "abcd", "none", "null", "undefined",
    "notarealkey", "not_a_real", "somekey", "secretkey", "mysecret", "s3cret",
    "hunter2", "foobar", "lorem",
)

PLACEHOLDER_SHAPES = (
    "${", "{{", "<%", "%s", "%(", "os.environ", "process.env", "getenv",
    "config.", "settings.", "self.", "this.", "env.", "vault:", "secrets.",
    "***", "...", "<", "$(", "#{",
)

DOC_LIKE = (
    "*.md", "*.mdx", "*.rst", "*.txt", "*.adoc",
    "*.example", "*.example.*", "*.sample", "*.sample.*", "*.template", "*.tpl",
    ".env.example", ".env.sample", ".env.template", ".env.dist",
    "*/fixtures/*", "fixtures/*", "*/testdata/*", "testdata/*",
    "*/__snapshots__/*",
)

ENV_FILE = re.compile(r"(?:^|/)\.env(?:\.[A-Za-z0-9_\-]+)?$")
ENV_SAFE_SUFFIX = re.compile(r"\.(?:example|sample|template|dist|defaults?)$")

KEY_FILE_EXTENSIONS = (
    ".pem", ".key", ".pfx", ".p12", ".jks", ".keystore", ".ppk", ".asc", ".gpg",
)
KEY_FILE_NAMES = (
    "id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".npmrc", ".pypirc",
    "credentials.json", "service-account.json", "serviceaccount.json",
    ".netrc", "_netrc", ".pgpass", "kubeconfig", ".htpasswd",
)


def shannon_entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def looks_like_placeholder(value: str) -> bool:
    lowered = value.lower()
    if any(token in lowered for token in PLACEHOLDER_TOKENS):
        return True
    if any(shape in value for shape in PLACEHOLDER_SHAPES):
        return True
    # repeated single character, e.g. "xxxxxxxxxxxx" or "0000000000"
    if len(set(lowered)) <= 3:
        return True
    return False


def _is_doc_like(path: str) -> bool:
    lowered = path.replace("\\", "/").lower()
    base = os.path.basename(lowered)
    for pattern in DOC_LIKE:
        if fnmatch.fnmatch(lowered, pattern) or fnmatch.fnmatch(base, pattern):
            return True
    return "/test/" in lowered or "/tests/" in lowered or lowered.startswith("tests/")


def _path_finding(path: str) -> Optional[Finding]:
    """Findings about the file itself rather than its contents."""
    normalized = path.replace("\\", "/")
    base = os.path.basename(normalized)
    lowered = base.lower()

    if ENV_FILE.search(normalized) and not ENV_SAFE_SUFFIX.search(lowered):
        return Finding(
            check="secrets",
            rule="env-file-committed",
            severity=BLOCK,
            title="Environment file is being committed",
            detail="`{}` normally holds live credentials for this project.".format(normalized),
            path=normalized,
            remediation=(
                "Add `{}` to .gitignore, run `git rm --cached {}` to untrack it, and commit a "
                "redacted `.env.example` instead.".format(base, normalized)
            ),
            fix_id="untrack:{}".format(normalized),
        )

    if lowered.endswith(KEY_FILE_EXTENSIONS):
        return Finding(
            check="secrets",
            rule="key-file-committed",
            severity=BLOCK,
            title="Key or certificate file is being committed",
            detail="`{}` has a private-key/credential file extension.".format(normalized),
            path=normalized,
            remediation=(
                "Untrack it with `git rm --cached {}` and load the key from a secret store or "
                "environment variable at runtime.".format(normalized)
            ),
            fix_id="untrack:{}".format(normalized),
        )

    if lowered in KEY_FILE_NAMES:
        return Finding(
            check="secrets",
            rule="credential-file-committed",
            severity=BLOCK,
            title="Credential file is being committed",
            detail="`{}` is a well-known credential file.".format(normalized),
            path=normalized,
            remediation="Untrack it with `git rm --cached {}` and keep it outside the repo.".format(
                normalized
            ),
            fix_id="untrack:{}".format(normalized),
        )
    return None


def run(ctx) -> List[Finding]:
    findings: List[Finding] = []
    seen = set()

    for path in ctx.files:
        finding = _path_finding(path)
        if finding is not None:
            findings.append(finding)

    entropy_enabled = bool(ctx.config.opt("secrets", "entropy", True))
    threshold = float(ctx.config.opt("secrets", "entropy_threshold", 4.2))
    min_len = int(ctx.config.opt("secrets", "min_entropy_length", 24))

    for path, lines in ctx.added.items():
        doc_like = _is_doc_like(path)
        for lineno, line in lines:
            if ctx.line_ignored(line):
                continue

            for rule_id, label, severity, pattern, group in PROVIDER_RULES:
                match = pattern.search(line)
                if not match:
                    continue
                value = match.group(group) if group else match.group(0)
                if group and looks_like_placeholder(value):
                    continue
                key = (rule_id, path, redact(value))
                if key in seen:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        check="secrets",
                        rule=rule_id,
                        severity=severity,
                        title="{} exposed in source".format(label),
                        detail="Matched `{}` at {}:{}.".format(rule_id, path, lineno),
                        path=path,
                        line=lineno,
                        evidence=redact(value),
                        remediation=(
                            "Remove the literal from the file and read it from an environment "
                            "variable instead. Treat this credential as compromised: rotate it now, "
                            "then purge it from history if it was ever committed "
                            "(`git filter-repo --invert-paths` or BFG)."
                        ),
                    )
                )

            if doc_like or not entropy_enabled:
                continue

            assignment = _sensitive_assignment(line)
            if assignment is None:
                continue
            name, value = assignment
            if len(value) < min_len or looks_like_placeholder(value):
                continue
            if shannon_entropy(value) < threshold:
                continue
            key = ("high-entropy-assignment", path, redact(value))
            if key in seen:
                continue
            seen.add(key)
            findings.append(
                Finding(
                    check="secrets",
                    rule="high-entropy-assignment",
                    severity=WARN,
                    title="Possible hardcoded secret",
                    detail=(
                        "`{}` is assigned a {}-character high-entropy literal at {}:{}."
                        .format(name, len(value), path, lineno)
                    ),
                    path=path,
                    line=lineno,
                    evidence=redact(value),
                    remediation=(
                        "If this is a real credential, move it to an environment variable and rotate "
                        "it. If it is a fixture or hash, add `# airbag:allow` to the line or "
                        "list the path under `allow.paths` in .airbag.json."
                    ),
                )
            )
    return findings


def _sensitive_assignment(line: str) -> Optional[Tuple[str, str]]:
    for match in ASSIGNMENT.finditer(line):
        name = match.group(1)
        if not SECRET_NAME.search(name):
            continue
        value = match.group("val")
        if not value:
            continue
        # Only alphanumeric-ish blobs look like credentials.
        if not re.fullmatch(r"[A-Za-z0-9+/=_\-\.]{8,200}", value):
            continue
        return name, value
    return None
