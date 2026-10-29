from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import unicodedata
from pathlib import Path
from typing import Iterable

MAX_TEXT_BYTES = 1_000_000
MANIFESTS = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "requirements.txt",
    "cargo.toml", "go.mod", "gemfile", "composer.json", "dockerfile",
}
HOOK_KEYS = {"preinstall", "install", "postinstall", "prepare", "prepublish", "prepublishonly"}
SINK_PATTERNS = {
    "process-execution": re.compile(r"\b(subprocess\.|os\.system\s*\(|child_process|execSync\s*\(|spawn\s*\()"),
    "dynamic-code": re.compile(r"\b(eval|exec)\s*\(|new\s+Function\s*\("),
    "shell-download": re.compile(r"\b(curl|wget)\b[^\n|;&]*(?:\||&&|;).{0,80}\b(sh|bash|python|node)\b", re.I),
}
NETWORK_PATTERNS = {
    "network-client": re.compile(r"\b(requests\.|urllib\.|httpx\.|fetch\s*\(|axios\.|https?\.request\s*\()"),
    "socket": re.compile(r"\b(socket\.|WebSocket\s*\()"),
}
CREDENTIAL_PATTERNS = {
    "environment-secret": re.compile(r"(?:process\.env|os\.environ|getenv\s*\()[^\n]{0,80}(?:TOKEN|SECRET|PASSWORD|API_KEY|PRIVATE_KEY)", re.I),
    "credential-path": re.compile(r"(?:\.aws/credentials|\.ssh/|\.npmrc|\.netrc|keychain|credential)", re.I),
}
HIDDEN_CATEGORIES = {"Cf"}
VARIATION_RANGES = ((0xFE00, 0xFE0F), (0xE0100, 0xE01EF))


class ScanIncomplete(RuntimeError):
    pass


def _run(args: list[str], cwd: Path, *, check: bool = True) -> subprocess.CompletedProcess[bytes]:
    try:
        return subprocess.run(args, cwd=cwd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE, check=check, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ScanIncomplete(f"{args[0]} failed: {exc}") from exc


def _trusted_root_alias(component: Path, info: os.stat_result) -> bool:
    """Return whether a symlink is an OS-owned alias directly beneath `/`.

    macOS exposes temporary directories through root-owned aliases such as
    ``/var -> /private/var`` and ``/tmp -> /private/tmp``.  Those aliases are
    outside an unprivileged caller's control, unlike a symlink introduced
    inside a repository path.
    """
    return component.parent == Path(component.anchor) and getattr(info, "st_uid", None) == 0


def _absolute_without_symlinked_ancestors(path: Path, *, allow_final_symlink: bool = False) -> Path:
    absolute = Path(os.path.abspath(os.fspath(path)))
    rewritten: set[Path] = set()
    while True:
        components = list(reversed(absolute.parents))
        if not allow_final_symlink:
            components.append(absolute)
        for component in components:
            try:
                info = component.lstat()
            except FileNotFoundError:
                if component == absolute:
                    raise
                continue
            if not stat.S_ISLNK(info.st_mode):
                continue
            if not _trusted_root_alias(component, info):
                raise ScanIncomplete(f"refusing symlinked path component: {component}")
            if component in rewritten:
                raise ScanIncomplete(f"cyclic root path alias: {component}")
            rewritten.add(component)
            remainder = absolute.relative_to(component)
            absolute = component.resolve(strict=True) / remainder
            break
        else:
            return absolute


def repository_root(path: Path) -> Path:
    candidate = _absolute_without_symlinked_ancestors(path)
    if candidate.is_file():
        candidate = candidate.parent
    result = _run(["git", "rev-parse", "--show-toplevel"], candidate)
    return _absolute_without_symlinked_ancestors(Path(os.fsdecode(result.stdout).strip()))


def tracked_entries(root: Path) -> list[tuple[str, str]]:
    # Git is the authority. We do not walk the target tree and do not follow links.
    output = _run(["git", "ls-files", "-s", "-z"], root).stdout
    entries: list[tuple[str, str]] = []
    for raw in output.split(b"\0"):
        if not raw:
            continue
        meta, name = raw.split(b"\t", 1)
        mode = os.fsdecode(meta.split(b" ", 1)[0])
        entries.append((os.fsdecode(name), mode))
    return entries


def _is_variation(cp: int) -> bool:
    return any(start <= cp <= end for start, end in VARIATION_RANGES)


def unicode_findings(text: str) -> list[dict]:
    findings = []
    line = column = 1
    for char in text:
        cp = ord(char)
        category = unicodedata.category(char)
        if category in HIDDEN_CATEGORIES or _is_variation(cp) or char in "\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069":
            findings.append({
                "line": line, "column": column, "codepoint": f"U+{cp:04X}",
                "name": unicodedata.name(char, "UNKNOWN"),
                "kind": "variation-selector" if _is_variation(cp) else "hidden-unicode",
            })
        if char == "\n":
            line, column = line + 1, 1
        else:
            column += 1
    return findings


def inspect_file(path: Path, *, display: str | None = None, mode: str | None = None) -> dict:
    label = display or str(path)
    result = {"path": label, "kind": "file", "size": 0, "sha256": None, "findings": []}
    try:
        info = path.lstat()
    except OSError as exc:
        raise ScanIncomplete(f"cannot stat {label}: {exc}") from exc
    if stat.S_ISLNK(info.st_mode) or mode == "120000":
        result["kind"] = "symlink"
        result["findings"].append({"severity": "medium", "type": "symlink", "detail": "not followed"})
        return result
    if not stat.S_ISREG(info.st_mode):
        result["kind"] = "non-regular"
        result["findings"].append({"severity": "high", "type": "non-regular", "detail": "not read"})
        return result
    classified = _run(["file", "--brief", "--mime-type", "--", str(path)], path.parent)
    result["fileType"] = os.fsdecode(classified.stdout).strip()
    digest = hashlib.sha256()
    prefix = bytearray()
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        opened = os.fstat(stream.fileno())
        if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (info.st_dev, info.st_ino):
            raise ScanIncomplete(f"file changed during scan: {label}")
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
            if len(prefix) < MAX_TEXT_BYTES:
                prefix.extend(chunk[:MAX_TEXT_BYTES - len(prefix)])
    result["size"] = opened.st_size
    result["sha256"] = digest.hexdigest()
    if mode == "100755" or (mode is None and info.st_mode & 0o111):
        result["findings"].append({"severity": "medium", "type": "executable-bit"})
    try:
        text = bytes(prefix).decode("utf-8")
    except UnicodeDecodeError:
        result["kind"] = "opaque"
        result["findings"].append({"severity": "high", "type": "opaque-file", "detail": "not decoded"})
        return result
    if opened.st_size > MAX_TEXT_BYTES:
        result["findings"].append({"severity": "medium", "type": "text-truncated", "detail": f"scanned first {MAX_TEXT_BYTES} bytes"})
    for item in unicode_findings(text):
        result["findings"].append({"severity": "high", "type": item["kind"], **item})
    lower_name = path.name.lower()
    if lower_name in MANIFESTS:
        result["findings"].append({"severity": "info", "type": "manifest"})
    if lower_name == "package.json":
        try:
            package = json.loads(text)
            scripts = package.get("scripts", {})
            for key in sorted(HOOK_KEYS.intersection(scripts if isinstance(scripts, dict) else {})):
                result["findings"].append({"severity": "high", "type": "install-hook", "hook": key})
        except json.JSONDecodeError:
            result["findings"].append({"severity": "high", "type": "invalid-manifest"})
    for group, patterns in (("execution", SINK_PATTERNS), ("network", NETWORK_PATTERNS), ("credential", CREDENTIAL_PATTERNS)):
        for name, pattern in patterns.items():
            if pattern.search(text):
                result["findings"].append({"severity": "medium", "type": f"{group}-surface", "pattern": name})
    return result


def inspect_tracked_file(path: Path) -> dict:
    absolute = _absolute_without_symlinked_ancestors(path, allow_final_symlink=True)
    root = repository_root(absolute.parent)
    try:
        relative = absolute.relative_to(root).as_posix()
    except ValueError as exc:
        raise ScanIncomplete("file is outside the repository") from exc
    tracked = dict(tracked_entries(root))
    if relative not in tracked:
        raise ScanIncomplete(f"file is not Git-tracked: {relative}")
    return inspect_file(absolute, display=relative, mode=tracked[relative])


def _gitleaks_status(root: Path) -> dict:
    binary = shutil.which("gitleaks")
    if not binary:
        return {"status": "skipped", "reason": "gitleaks is not installed"}
    try:
        run = subprocess.run([binary, "git", "--no-banner", "--redact", "--exit-code", "1"],
                             cwd=root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.PIPE, timeout=120)
    except (OSError, subprocess.SubprocessError) as exc:
        return {"status": "incomplete", "reason": str(exc)}
    if run.returncode == 0:
        return {"status": "clean", "tool": "gitleaks"}
    if run.returncode == 1:
        return {"status": "findings", "tool": "gitleaks"}
    return {"status": "incomplete", "tool": "gitleaks", "reason": f"exit {run.returncode}"}


def scan_repository(path: Path) -> dict:
    root = repository_root(path)
    files = [inspect_file(root / name, display=name, mode=mode) for name, mode in tracked_entries(root)]
    findings = [{"path": item["path"], **finding} for item in files for finding in item["findings"]]
    history = _gitleaks_status(root)
    incomplete = history["status"] == "incomplete"
    return {
        "schemaVersion": 1,
        "root": str(root),
        "trackedFiles": len(files),
        "historySecretScan": history,
        "findings": findings,
        "summary": {
            "high": sum(f.get("severity") == "high" for f in findings),
            "medium": sum(f.get("severity") == "medium" for f in findings),
            "historySecretFindings": history["status"] == "findings",
            "incomplete": incomplete,
        },
    }


def scan_unicode(paths: Iterable[Path]) -> dict:
    reports = []
    for supplied in paths:
        absolute = _absolute_without_symlinked_ancestors(supplied, allow_final_symlink=True)
        info = absolute.lstat()
        if stat.S_ISDIR(info.st_mode):
            root = repository_root(absolute)
            candidates = [(root / name, name, mode) for name, mode in tracked_entries(root)]
        else:
            report = inspect_tracked_file(absolute)
            candidates = []
            hits = [f for f in report["findings"] if f["type"] in {"hidden-unicode", "variation-selector"}]
            if hits:
                reports.append({"path": report["path"], "findings": hits})
        for path, label, mode in candidates:
            report = inspect_file(path, display=label, mode=mode)
            hits = [f for f in report["findings"] if f["type"] in {"hidden-unicode", "variation-selector"}]
            if hits:
                reports.append({"path": label, "findings": hits})
    return {"schemaVersion": 1, "files": reports, "findingCount": sum(len(r["findings"]) for r in reports)}

