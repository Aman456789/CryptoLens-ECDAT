#!/usr/bin/env python3
"""
scanner-cli/scanner.py

Runs Semgrep against a target repository, signs the findings, and
streams them to the ECDAT backend's /api/ingest/batch endpoint in
bounded, HMAC-signed NDJSON batches.
"""

import hashlib
import hmac
import json
import logging
import os
import re
import subprocess
import sys
from pathlib import Path

import requests

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("ecdat-scanner")

BATCH_SIZE = 200
REQUEST_TIMEOUT_SECONDS = 10

RULES_PATH = os.environ.get("ECDAT_RULES_PATH", "/app/rules/custom-crypto-rules.yaml")
BACKEND_URL = os.environ.get("BACKEND_URL", "http://backend:5000")
ECDAT_TOKEN = os.environ.get("ECDAT_TOKEN")
PROJECT_SECRET = os.environ.get("PROJECT_SECRET")


def run_semgrep(repo_root: str) -> dict:
    """
    Run Semgrep with cwd=repo_root and target "." so every result's
    `path` comes back repo-relative (e.g. "src/auth.js") rather than
    absolute or dependent on however the caller invoked this script.
    """
    cmd = ["semgrep", "--config", RULES_PATH, "--json", "--quiet", "--no-git-ignore", "."]
    log.info("running semgrep in %s", repo_root)

    try:
        proc = subprocess.run(cmd, cwd=repo_root, capture_output=True, text=True)
    except FileNotFoundError:
        log.error("semgrep executable not found on PATH — is it installed?")
        sys.exit(1)

    # semgrep exits 1 when findings exist — that's success, not failure.
    # Anything else means semgrep itself errored (bad rules, crash, etc).
    if proc.returncode not in (0, 1):
        log.error("semgrep failed (exit %s): %s", proc.returncode, proc.stderr.strip())
        sys.exit(1)

    try:
        return json.loads(proc.stdout)
    except json.JSONDecodeError as exc:
        log.error("could not parse semgrep output as JSON: %s", exc)
        sys.exit(1)


EXTENSION_TO_LANGUAGE = {
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".py": "python",
    ".java": "java",
    ".go": "go",
    ".rb": "ruby",
    ".php": "php",
    ".c": "c",
    ".cpp": "cpp",
    ".cs": "csharp",
}


def infer_language(rel_path: str) -> str:
    """Best-effort language tag derived from the file extension, since the
    backend's PQC prompt (and its cache key) needs a language, and Semgrep's
    own output doesn't carry one directly."""
    suffix = Path(rel_path).suffix.lower()
    return EXTENSION_TO_LANGUAGE.get(suffix, "unknown")


def infer_key_size(algorithm: str) -> "int | None":
    """Pull a trailing numeric key size out of an algorithm tag like
    'RSA-1024' -> 1024. Returns None when the algorithm carries no size
    (e.g. 'MD5'), which is a legitimate, expected case downstream."""
    match = re.search(r"(\d+)\s*$", algorithm or "")
    return int(match.group(1)) if match else None


def extract_snippet(repo_root: str, rel_path: str, start_line: int, end_line: int) -> str:
    """
    Read the exact vulnerable snippet directly from disk using the
    match's own line range.

    Not sourced from Semgrep's `extra.lines` field: confirmed against a
    live install (semgrep 1.176.1) that this field — and `fingerprint` —
    are gated behind a Semgrep AppSec Platform login and return the
    literal string "requires login" instead of the matched source for
    an unauthenticated local run. Reading the file ourselves removes
    that dependency entirely.
    """
    try:
        lines = Path(repo_root, rel_path).read_text(errors="replace").splitlines()
        return "\n".join(lines[start_line - 1:end_line])
    except OSError as exc:
        log.warning("could not read snippet from %s: %s", rel_path, exc)
        return ""


def normalize_findings(semgrep_report: dict, repo_root: str) -> list:
    """Map raw Semgrep results onto the shape /api/ingest/batch expects.

    IMPORTANT: the backend's ingestController.js reads `code`, `language`,
    and `keySize` off each finding to build the AI-verification and PQC-fix
    jobs (see verificationQueue.js / nvidiaLlmService.js). Renaming or
    dropping these fields silently breaks that pipeline downstream —
    every job would carry `snippet: undefined` instead of failing loudly.
    """
    findings = []
    for result in semgrep_report.get("results", []):
        start = result["start"]
        end = result["end"]
        rel_path = result["path"]
        algorithm = result["check_id"].split(".")[-1]

        findings.append({
            # required by the Asset schema's enum(['semgrep','nmap']) — this
            # was previously omitted entirely, so every ingested finding had
            # source: undefined until the network-scan path separately set it.
            "source": "semgrep",
            "filePath": rel_path,
            "line": start["line"],
            "column": start["col"],
            "algorithm": algorithm,
            # the RAW vulnerable snippet — this is "code" the backend sends
            # for AI verification and, once masked, for PQC fix generation.
            # It is NOT itself a fix; do not call this field fixSnippet.
            "code": extract_snippet(repo_root, rel_path, start["line"], end["line"]),
            "language": infer_language(rel_path),
            "keySize": infer_key_size(algorithm),
            "severity": result.get("extra", {}).get("severity", "WARNING"),
            "message": result.get("extra", {}).get("message", ""),
        })
    return findings


def sign_payload(payload_bytes: bytes) -> str:
    if not PROJECT_SECRET:
        log.error("PROJECT_SECRET is not set — cannot sign the ingest payload")
        sys.exit(1)
    digest = hmac.new(PROJECT_SECRET.encode(), payload_bytes, hashlib.sha256).hexdigest()
    return f"sha256={digest}"


def stream_findings(findings: list) -> None:
    """
    Stream findings to /api/ingest/batch in fixed-size batches of
    BATCH_SIZE. Never one unbounded payload — Express's body-size limit
    is a fixed ceiling any large enough scan eventually exceeds, and
    batching removes the ceiling rather than moving it.
    """
    if not ECDAT_TOKEN:
        log.error("ECDAT_TOKEN is not set — cannot authenticate to the backend")
        sys.exit(1)
    if not findings:
        log.info("no findings to report")
        return

    total_batches = (len(findings) + BATCH_SIZE - 1) // BATCH_SIZE
    endpoint = f"{BACKEND_URL.rstrip('/')}/api/ingest/batch"

    for batch_index in range(total_batches):
        batch = findings[batch_index * BATCH_SIZE: (batch_index + 1) * BATCH_SIZE]

        # Sign and send the SAME bytes object — the signature must cover
        # exactly what goes out on the wire, so this is built once and
        # passed to requests as raw `data`, never re-serialized via `json=`.
        payload_bytes = json.dumps(
            {"findings": batch, "batchIndex": batch_index},
            separators=(",", ":"),
        ).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "X-ECDAT-Token": ECDAT_TOKEN,
            "X-ECDAT-Signature": sign_payload(payload_bytes),
        }

        log.info("streaming batch %d/%d (%d findings)", batch_index + 1, total_batches, len(batch))

        resp = requests.post(endpoint, data=payload_bytes, headers=headers, timeout=REQUEST_TIMEOUT_SECONDS)
        resp.raise_for_status()  # fail loud — don't swallow a rejected batch


def main() -> None:
    repo_root = os.path.abspath(sys.argv[1] if len(sys.argv) > 1 else ".")
    log.info("scanning %s", repo_root)

    report = run_semgrep(repo_root)
    findings = normalize_findings(report, repo_root)
    log.info("found %d finding(s)", len(findings))

    stream_findings(findings)
    log.info("done")


if __name__ == "__main__":
    main()
