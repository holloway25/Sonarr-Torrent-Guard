"""Exercise private filename rejection through both checker CLI modes."""
from pathlib import Path
import subprocess
import shutil
import sys
import tempfile
import unittest


CHECKER = Path(__file__).resolve().parents[1] / "privacy_check.py"


# Repository-only tooling is exercised by source CI; the runtime image has no Git.
@unittest.skipUnless(shutil.which("git"), "Repository privacy CLI requires Git")
class PrivacyFilenameTests(unittest.TestCase):
    def test_private_configuration_families_in_staged_and_tracked_files(self):
        names = (".env", ".env.production", ".ENV.production", "connections.json",
                 "connections.production.json", "connections-local.json",
                 "nested/connections.production.json")
        for name in names:
            with self.subTest(name=name), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                subprocess.run(["git", "init", "-q", directory], check=True)
                target = root / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text('{"password": "opaque-value"}', encoding="utf-8")
                subprocess.run(["git", "-C", directory, "add", "--", name], check=True)
                for flags in ([], ["--all"]):
                    result = subprocess.run([sys.executable, str(CHECKER), *flags],
                                            cwd=root, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("prohibited runtime or handoff artifact", result.stdout)
                    self.assertNotIn("opaque-value", result.stdout + result.stderr)

    def test_generic_configuration_example_remains_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", directory], check=True)
            (Path(directory) / "settings.example.json").write_text("{}", encoding="utf-8")
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            for flags in ([], ["--all"]):
                result = subprocess.run([sys.executable, str(CHECKER), *flags],
                                        cwd=directory, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
