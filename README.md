# Repo First Look

[![CI](https://github.com/0xreconlion/repo-first-look/actions/workflows/ci.yml/badge.svg)](https://github.com/0xreconlion/repo-first-look/actions/workflows/ci.yml)

**Maturity:** v0.1.0 candidate — in development and not yet released.

Repo First Look is a static first-pass inspection tool for an unfamiliar Git repository. It inventories review surfaces without building, importing, installing, or executing target code.

```console
repo-first-look scan PATH [--format text|json]
repo-first-look file FILE [--format text|json]
repo-first-look unicode PATH... [--format text|json]
repo-first-look variation FILE... [--format json]
```

It inspects only Git-tracked files, does not follow symlinks, and never prints decoded concealed payloads. It reports opaque files, executable bits, manifests and install hooks, execution sinks, network and credential surfaces, hidden Unicode, and full-history secret-scan status. Gitleaks is optional; when unavailable the result is explicitly `skipped`, never `clean`.

Exit status is `0` for a completed scan without high-risk findings, `1` when findings are present, and `2` for invalid input or an incomplete scan.

Requirements: Python 3.11+, Git, and the `file` utility. Linux and macOS are supported. Windows compatibility is not currently claimed.

```console
python3 -m pip install .
repo-first-look scan .
python3 -m unittest discover -s tests
```

This is triage, not a malware verdict. Pattern matches identify review work; they do not prove malicious behavior.

