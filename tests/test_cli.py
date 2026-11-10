import json
import io
import os
import subprocess
import sys
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).parents[1]
sys.path.insert(0, str(ROOT / "src"))
from repo_first_look.cli import main
from repo_first_look.core import (
    _absolute_without_symlinked_ancestors,
    _trusted_root_alias,
    inspect_file,
    inspect_tracked_file,
    scan_repository,
)


class RepoFirstLookTests(unittest.TestCase):
    def make_repo(self):
        temp = tempfile.TemporaryDirectory()
        root = Path(temp.name)
        subprocess.run(["git", "init", "-q"], cwd=root, check=True)
        marker = root / "EXECUTED"
        hook = root / "hook.sh"
        hook.write_text(f"#!/bin/sh\ntouch {marker}\n", encoding="utf-8")
        hook.chmod(0o755)
        (root / "package.json").write_text(json.dumps({"scripts": {"postinstall": f"touch {marker}"}}), encoding="utf-8")
        binary = root / "payload.bin"
        binary.write_bytes(b"\x00\xff\x00sentinel")
        link = root / "outside-link"
        link.symlink_to("/etc/passwd")
        subprocess.run(["git", "add", "hook.sh", "package.json", "payload.bin", "outside-link"], cwd=root, check=True)
        return temp, root, marker

    def test_scan_never_executes_hooks_or_binaries(self):
        temp, root, marker = self.make_repo()
        self.addCleanup(temp.cleanup)
        report = scan_repository(root)
        self.assertFalse(marker.exists())
        kinds = {(f["path"], f["type"]) for f in report["findings"]}
        self.assertIn(("package.json", "install-hook"), kinds)
        self.assertIn(("payload.bin", "opaque-file"), kinds)
        self.assertIn(("outside-link", "symlink"), kinds)

    def test_file_scan_does_not_execute_executable(self):
        temp, root, marker = self.make_repo()
        self.addCleanup(temp.cleanup)
        report = inspect_tracked_file(root / "hook.sh")
        self.assertFalse(marker.exists())
        self.assertTrue(any(f["type"] == "executable-bit" for f in report["findings"]))
        self.assertEqual(report["fileType"], "text/x-shellscript")

    def test_explicit_file_requires_git_tracking_and_never_follows_symlinks(self):
        temp, root, marker = self.make_repo()
        self.addCleanup(temp.cleanup)
        (root / "untracked.txt").write_text("not in the index", encoding="utf-8")
        self.assertEqual(main(["file", str(root / "untracked.txt")]), 2)
        report = inspect_tracked_file(root / "outside-link")
        self.assertEqual(report["kind"], "symlink")
        self.assertIsNone(report["sha256"])
        alias = root.parent / f"{root.name}-alias"
        alias.symlink_to(root, target_is_directory=True)
        self.addCleanup(alias.unlink)
        self.assertEqual(main(["file", str(alias / "hook.sh")]), 2)
        self.assertFalse(marker.exists())

    def test_os_owned_root_alias_is_canonicalized_but_user_alias_is_not_trusted(self):
        temp, root, marker = self.make_repo()
        self.addCleanup(temp.cleanup)
        alias = root.parent / f"{root.name}-system-alias"
        alias.symlink_to(root, target_is_directory=True)
        self.addCleanup(alias.unlink)
        # Trust this alias *in addition to* whatever the real rule already
        # trusts, rather than instead of it. The temporary directory itself can
        # sit under a genuine OS root alias — macOS hands out `/var/folders/...`
        # and `/var` is a root-owned symlink — so replacing the rule outright
        # makes the walk refuse the fixture's own parent before it ever reaches
        # the component under test.
        #
        # Compare resolved targets, not path objects. Once an ancestor alias has
        # been rewritten the walk spells this component `/private/var/...` while
        # the fixture built it as `/var/...`; those are the same alias and an
        # identity comparison still misses it.
        resolved_alias = alias.resolve()
        with mock.patch(
            "repo_first_look.core._trusted_root_alias",
            side_effect=lambda component, info: component.resolve() == resolved_alias
            or _trusted_root_alias(component, info),
        ):
            canonical = _absolute_without_symlinked_ancestors(alias / "hook.sh")
        # The expected value has to be canonical too. Returning a path free of
        # symlinked ancestors is the whole contract, so where the temporary
        # directory itself sits under an OS alias the result is spelled
        # `/private/var/...` and comparing against the fixture's own `/var/...`
        # spelling fails on a correct result.
        self.assertEqual(canonical, root.resolve() / "hook.sh")
        self.assertFalse(marker.exists())

    def test_invalid_input_is_exit_two(self):
        self.assertEqual(main(["scan", "/definitely/missing"]), 2)

    def test_hidden_unicode_is_reported_without_source_text(self):
        with tempfile.TemporaryDirectory() as d:
            target = Path(d) / "x.txt"
            target.write_text("safe\u202eevil", encoding="utf-8")
            report = inspect_file(target)
            self.assertTrue(any(f["type"] == "hidden-unicode" for f in report["findings"]))
            self.assertNotIn("safe", json.dumps(report))

    def test_history_secret_findings_return_exit_one(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q"], cwd=root, check=True)
            (root / "README.md").write_text("plain fixture\n", encoding="utf-8")
            subprocess.run(["git", "add", "README.md"], cwd=root, check=True)
            with mock.patch("repo_first_look.core._gitleaks_status", return_value={"status": "findings", "tool": "gitleaks"}), redirect_stdout(io.StringIO()):
                self.assertEqual(main(["scan", str(root), "--format", "json"]), 1)


if __name__ == "__main__":
    unittest.main()

