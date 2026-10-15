"""CLI Spec checks for the ds339 entry point. No USB device."""

import json
import subprocess
import sys
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent
BIN = [sys.executable, str(ROOT / "ds339.py")]


def _run(args: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(BIN + args, capture_output=True, text=True, check=False)


class CliSpecTest(unittest.TestCase):
    def test_schema_offline(self) -> None:
        done = _run(["schema"])
        self.assertEqual(done.returncode, 0, done.stderr)
        doc = json.loads(done.stdout)
        self.assertEqual(doc["clispec"], "0.3")
        self.assertEqual(doc["name"], "ds339")
        self.assertEqual(doc["version"], "0.1.0")
        self.assertEqual(doc["output"]["piped"], "text")
        self.assertEqual(doc["output"]["tty"], "text")
        names = [cmd["name"] for cmd in doc["commands"]]
        self.assertIn("schema", names)
        self.assertIn("probe", names)
        self.assertIn("version", names)
        kinds = {err["kind"]: err["exit_code"] for err in doc["errors"]}
        self.assertEqual(kinds["usage"], 2)
        self.assertEqual(kinds["failure"], 1)

    def test_schema_filter(self) -> None:
        done = _run(["schema", "probe"])
        self.assertEqual(done.returncode, 0, done.stderr)
        doc = json.loads(done.stdout)
        self.assertEqual([cmd["name"] for cmd in doc["commands"]], ["probe"])

    def test_version_text_is_not_json(self) -> None:
        done = _run(["-o", "text", "version"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(done.stdout, "ds339 0.1.0\n")
        self.assertFalse(done.stdout.startswith("{"))

    def test_version_json(self) -> None:
        done = _run(["-o", "json", "version"])
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertEqual(json.loads(done.stdout), {"version": "0.1.0"})

    def test_json_usage_envelope(self) -> None:
        done = _run(["-o", "json", "schema", "nope"])
        self.assertEqual(done.returncode, 2)
        last = done.stderr.strip().splitlines()[-1]
        self.assertEqual(json.loads(last)["error"]["kind"], "usage")

    def test_bad_output_is_not_json(self) -> None:
        done = _run(["-o", "nope", "version"])
        self.assertEqual(done.returncode, 2)
        self.assertFalse(done.stderr.strip().splitlines()[-1].startswith("{"))


if __name__ == "__main__":
    unittest.main()
