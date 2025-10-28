import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


SCRIPT_PATH = Path(__file__).resolve().parent / "sentinel_fim.py"


def run_cli(args, cwd: Path) -> subprocess.CompletedProcess:
    command = [sys.executable, str(SCRIPT_PATH), *args]
    return subprocess.run(
        command,
        cwd=cwd,
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )


class SentinelFIMTests(unittest.TestCase):
    def setUp(self) -> None:
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.root = Path(self.tempdir.name)

    def write(self, relative: str, content: str) -> None:
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(content, encoding="utf-8")

    def read_baseline(self) -> dict:
        baseline_path = self.root / ".sentinel_fim.json"
        return json.loads(baseline_path.read_text(encoding="utf-8"))

    def test_init_creates_baseline(self) -> None:
        self.write("file1.txt", "hello")
        self.write("sub/file2.txt", "world")

        result = run_cli(["init", str(self.root)], self.root)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        baseline = self.read_baseline()
        self.assertEqual(
            set(baseline["files"].keys()), {"file1.txt", "sub/file2.txt"}
        )

    def test_scan_detects_changes_and_exit_codes(self) -> None:
        self.write("alpha.txt", "alpha")
        self.write("beta.txt", "beta")

        init_result = run_cli(["init", str(self.root)], self.root)
        self.assertEqual(init_result.returncode, 0, msg=init_result.stderr)

        # No changes should yield exit code 0
        clean_scan = run_cli(["scan", str(self.root)], self.root)
        self.assertEqual(clean_scan.returncode, 0, msg=clean_scan.stderr)

        # Modify, add, delete files
        self.write("alpha.txt", "alpha updated")
        (self.root / "beta.txt").unlink()
        self.write("gamma.txt", "gamma")

        report_path = self.root / "report.json"
        scan_result = run_cli(["scan", str(self.root), "--report", str(report_path)], self.root)
        self.assertEqual(scan_result.returncode, 2, msg=scan_result.stderr)

        report = json.loads(report_path.read_text(encoding="utf-8"))

        added_paths = {entry["path"] for entry in report["added"]}
        self.assertEqual(added_paths, {"gamma.txt"})

        modified_paths = {entry["path"] for entry in report["modified"]}
        self.assertEqual(modified_paths, {"alpha.txt"})

        deleted_paths = {entry["path"] for entry in report["deleted"]}
        self.assertEqual(deleted_paths, {"beta.txt"})

    def test_ignore_rules_applied(self) -> None:
        self.write("keep.txt", "keep")
        self.write("logs/app.log", "ignore")
        self.write(".sentinelignore", "*.log\n")

        result = run_cli(["init", str(self.root)], self.root)
        self.assertEqual(result.returncode, 0, msg=result.stderr)

        baseline = self.read_baseline()
        self.assertEqual(set(baseline["files"].keys()), {"keep.txt"})


if __name__ == "__main__":  # pragma: no cover
    unittest.main()
