import base64
import json
import os
import tempfile
import unittest
from unittest.mock import patch

import free_scan_issue as free


class FreeScanTests(unittest.TestCase):
    def test_extract_repo(self):
        self.assertEqual(
            free.extract_repo("### Public GitHub repository URL\nhttps://github.com/acme/demo\n"),
            ("acme", "demo"),
        )

    def test_scan_uses_api_blobs_without_executing_code(self):
        files = {
            "AGENTS.md": "Keep permissions narrow.\n",
            ".github/workflows/ci.yml": "permissions: write-all\n",
            "config.txt": "token=" + "sk_live_" + "A" * 24 + "\n",
        }
        def fake_get(path, token):
            if path == "/repos/acme/demo":
                return {"private": False, "size": 10, "default_branch": "main"}
            if "/git/ref/heads/" in path:
                return {"object": {"sha": "commitsha"}}
            if path.endswith("/git/commits/commitsha"):
                return {"tree": {"sha": "treesha"}}
            if "/git/trees/treesha" in path:
                return {
                    "truncated": False,
                    "tree": [
                        {"type": "blob", "path": name, "size": len(text), "sha": "sha-" + str(i)}
                        for i, (name, text) in enumerate(files.items())
                    ],
                }
            if "/git/blobs/" in path:
                idx = int(path.rsplit("-", 1)[-1])
                text = list(files.values())[idx]
                return {"encoding": "base64", "content": base64.b64encode(text.encode()).decode()}
            raise AssertionError(path)

        with patch.object(free, "api_get", side_effect=fake_get):
            report = free.scan_public_repo("acme", "demo", "token")
        kinds = {item["kind"] for item in report["findings"]}
        self.assertIn("workflow-write-all", kinds)
        self.assertIn("stripe-secret-key", kinds)
        self.assertNotIn("sk_live_" + "A" * 24, json.dumps(report))

    def test_private_repo_rejected(self):
        with patch.object(free, "api_get", return_value={"private": True, "size": 1, "default_branch": "main"}):
            with self.assertRaises(ValueError):
                free.scan_public_repo("acme", "private", None)

    def test_large_repo_rejected(self):
        with patch.object(free, "api_get", return_value={"private": False, "size": free.MAX_REPO_KB + 1, "default_branch": "main"}):
            with self.assertRaises(ValueError):
                free.scan_public_repo("acme", "huge", None)


if __name__ == "__main__":
    unittest.main()
