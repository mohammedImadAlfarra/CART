"""The lab catalogue: every target, its port, login, source file and GROUND TRUTH.

Ground truth is the real answer key. The scanner never reads it; the benchmark
uses it to score precision / recall per vulnerability type.

The lab covers the same three attack families the ML model learns from the
dataset: SQL injection, cross-site scripting (XSS) and path traversal.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from . import sites

BASE = Path(__file__).resolve().parent
SITES_SRC = BASE / "sites.py"
FILES_STATE = BASE / "_state_files"   # where the CloudFiles canary lives


@dataclass
class Target:
    name: str
    title: str
    port: int
    theme: str                       # the vuln class this site is "about"
    ground_truth: list[dict]
    build: callable                  # (fixes_path) -> Flask app
    source: Path
    auth: dict = field(default_factory=dict)
    decoys: list[str] = field(default_factory=list)

    @property
    def base_url(self):
        return f"http://127.0.0.1:{self.port}"


TARGETS: list[Target] = [
    Target(
        name="bank", title="MicroBank", port=5001, theme="SQL injection",
        ground_truth=[
            {"id": "BANK-1", "type": "sqli_auth_bypass", "path": "/login", "fix": "sqli_login"},
            {"id": "BANK-2", "type": "sqli", "path": "/accounts", "fix": "sqli_search"},
        ],
        build=sites.make_bank, source=SITES_SRC, auth={"username": "sara", "password": "sara2024"},
    ),
    Target(
        name="blog", title="DevBlog", port=5002, theme="Cross-site scripting (XSS)",
        ground_truth=[
            {"id": "BLOG-1", "type": "xss_reflected", "path": "/search", "fix": "xss_search"},
            {"id": "BLOG-2", "type": "xss_reflected", "path": "/comment", "fix": "xss_comment"},
        ],
        build=sites.make_blog, source=SITES_SRC, decoys=["/hello"],
    ),
    Target(
        name="files", title="CloudFiles", port=5003, theme="Path traversal",
        ground_truth=[
            {"id": "FILE-1", "type": "path_traversal", "path": "/download", "fix": "path_traversal"},
        ],
        build=lambda fp: sites.make_files(fp, FILES_STATE), source=SITES_SRC, decoys=["/view"],
    ),
    Target(
        name="clean", title="SecureCorp", port=5004, theme="No vulnerabilities (false-positive control)",
        ground_truth=[],
        build=sites.make_clean, source=SITES_SRC, decoys=["/search", "/profile"],
    ),
]

BY_NAME = {t.name: t for t in TARGETS}


def get(names=None) -> list[Target]:
    if not names:
        return TARGETS
    return [BY_NAME[n] for n in names if n in BY_NAME]
