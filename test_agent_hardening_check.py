import json
import tempfile
import unittest
from pathlib import Path
from contextlib import redirect_stdout
from io import StringIO

import agent_hardening_check as scanner


class ScannerTests(unittest.TestCase):
    def test_inventory_and_safe_secret_reporting(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "AGENTS.md").write_text("Keep changes scoped.\n", encoding="utf-8")
            (root / "package.json").write_text('{"name":"demo"}\n', encoding="utf-8")
            workflow = root / ".github" / "workflows"
            workflow.mkdir(parents=True)
            (workflow / "ci.yml").write_text("permissions: write-all\npull_request_target:\n", encoding="utf-8")
            token = "sk_live_" + "A" * 24
            (root / "config.txt").write_text("token=" + token + "\n", encoding="utf-8")

            report = scanner.scan(root)
            self.assertIn("AGENTS.md", report["inventory"]["agent_instruction_files"])
            self.assertIn("package.json", report["inventory"]["dependency_manifests"])
            kinds = {f["kind"] for f in report["findings"]}
            self.assertIn("stripe-secret-key", kinds)
            self.assertIn("workflow-write-all", kinds)
            self.assertIn("pull-request-target", kinds)
            encoded = json.dumps(report)
            self.assertNotIn(token, encoded)

    def test_skips_scanner_itself(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            (root / "agent_hardening_check.py").write_text("--dangerously-skip-permissions", encoding="utf-8")
            report = scanner.scan(root)
            self.assertEqual(report["summary"]["total"], 0)

    def test_skips_git_and_node_modules(self):
        with tempfile.TemporaryDirectory() as td:
            root = Path(td)
            for folder in [".git", "node_modules"]:
                p = root / folder
                p.mkdir()
                (p / "secret.txt").write_text("ghp_" + "B" * 24, encoding="utf-8")
            report = scanner.scan(root)
            self.assertEqual(report["summary"]["total"], 0)


    def test_fail_thresholds(self):
        report = {
            "summary": {"high": 1, "medium": 0, "low": 0, "total": 1}
        }
        self.assertFalse(scanner.should_fail(report, "never"))
        self.assertTrue(scanner.should_fail(report, "high"))
        self.assertTrue(scanner.should_fail(report, "medium"))
        self.assertTrue(scanner.should_fail(report, "any"))

    def test_skips_symlinked_files(self):
        with tempfile.TemporaryDirectory() as td, tempfile.TemporaryDirectory() as outside:
            root = Path(td)
            target = Path(outside) / "secret.txt"
            token = "sk_live_" + "C" * 24
            target.write_text(token, encoding="utf-8")
            link = root / "linked-secret.txt"
            try:
                link.symlink_to(target)
            except OSError:
                self.skipTest("symlink creation is not available in this environment")
            report = scanner.scan(root)
            self.assertEqual(report["summary"]["total"], 0)

    def test_markdown_contains_cta_and_limitations(self):
        with tempfile.TemporaryDirectory() as td:
            report = scanner.scan(Path(td))
            output = scanner.markdown(report)
            self.assertIn("not a security certification", output.lower())
            self.assertIn("ai-agent-hardening/audit.html", output)

if __name__ == "__main__":
    unittest.main()
