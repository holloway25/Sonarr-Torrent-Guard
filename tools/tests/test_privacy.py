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
    def test_private_runtime_files_in_staged_and_tracked_checks(self):
        names = (".env", ".env.production", ".ENV.production", "connections.json",
                 "connections.production.json", "connections-local.json",
                 "nested/connections.production.json", ".connections-validation.json",
                 "nested/.guard-sample", "nested/routine.log.1")
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

    def test_private_environment_file_is_ignored_and_forced_credential_assignments_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            subprocess.run(["git", "init", "-q", directory], check=True)
            source_ignore = (CHECKER.parent.parent / ".gitignore").read_text()
            (root / ".gitignore").write_text(source_ignore)
            credential = "a" * 32
            for name in ("guard.env", "deployment.temporary"):
                (root / name).write_text(f"STGUARD_SONARR_HD_API_KEY={credential}\n", encoding="utf-8")
            ignored = subprocess.run(["git", "check-ignore", "--quiet", "--", "guard.env"], cwd=root)
            self.assertEqual(ignored.returncode, 0)
            subprocess.run(["git", "add", "--force", "--", "guard.env", "deployment.temporary"], cwd=root, check=True)
            for flags in ([], ["--all"]):
                result = subprocess.run([sys.executable, str(CHECKER), *flags],
                                        cwd=root, capture_output=True, text=True)
                self.assertEqual(result.returncode, 1, result.stderr)
                self.assertIn("guard.env: prohibited runtime or handoff artifact", result.stdout)
                for name in ("guard.env", "deployment.temporary"):
                    self.assertIn(name + ": non-placeholder credential", result.stdout)
                self.assertNotIn(credential, result.stdout + result.stderr)

    def test_container_environment_example_requires_placeholders(self):
        for field, value, reason in (
                ("STGUARD_SONARR_HD_API_KEY", "a" * 32, "credential"),
                ("STGUARD_SONARR_UHD_API_KEY", "b" * 32, "credential"),
                ("STGUARD_QBIT_USERNAME", "opaque-user", "credential"),
                ("STGUARD_QBIT_PASSWORD", "opaque-password", "credential"),
                ("STGUARD_QBIT_URL", "https://downloader.example.invalid.other.invalid", "endpoint")):
            with self.subTest(field=field), tempfile.TemporaryDirectory() as directory:
                subprocess.run(["git", "init", "-q", directory], check=True)
                example = Path(directory) / "deploy" / "container.env.example"
                example.parent.mkdir()
                example.write_text(f"export {field} = {value}\n", encoding="utf-8")
                subprocess.run(["git", "-C", directory, "add", "."], check=True)
                for flags in ([], ["--all"]):
                    result = subprocess.run([sys.executable, str(CHECKER), *flags],
                                            cwd=directory, capture_output=True, text=True)
                    self.assertEqual(result.returncode, 1, result.stderr)
                    self.assertIn("non-placeholder " + reason, result.stdout)
                    self.assertNotIn(value, result.stdout + result.stderr)

    def test_generic_configuration_example_remains_allowed(self):
        with tempfile.TemporaryDirectory() as directory:
            subprocess.run(["git", "init", "-q", directory], check=True)
            (Path(directory) / "settings.example.json").write_text("{}", encoding="utf-8")
            subprocess.run(["git", "-C", directory, "add", "."], check=True)
            for flags in ([], ["--all"]):
                result = subprocess.run([sys.executable, str(CHECKER), *flags],
                                        cwd=directory, capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
