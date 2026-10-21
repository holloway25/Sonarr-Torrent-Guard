from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from tools import dependency_release as policy


class DependencyReleaseTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(__file__).resolve().parents[2]
        self.inputs = {name: (self.root / name).read_bytes() for name in (*policy.IMAGE_FILES, "Dockerfile")}

    def test_only_base_digest_change_is_automatic(self):
        candidate = dict(self.inputs)
        source = candidate["Dockerfile"].decode()
        candidate["Dockerfile"] = policy.FROM.sub("FROM " + policy.BASE + "@sha256:" + "a" * 64 + "\n", source, count=1).encode()
        policy.compare(candidate, self.inputs)

    def test_every_image_source_file_and_license_change_needs_review(self):
        for name in policy.IMAGE_FILES:
            candidate = dict(self.inputs)
            candidate[name] += b"\n# deliberate change\n"
            with self.subTest(name=name), self.assertRaises(policy.DependencyReviewRequired):
                policy.compare(candidate, self.inputs)

    def test_added_or_missing_image_inputs_cannot_be_ignored(self):
        for candidate in (dict(self.inputs, **{"payload.py": b"unexpected"}),
                          {k: v for k, v in self.inputs.items() if k != "guard.py"}):
            with self.assertRaises(policy.DependencyReviewRequired):
                policy.compare(candidate, self.inputs)

    def test_fingerprint_manifest_exactly_covers_actual_image_copy_sources(self):
        copied = [name for line in self.inputs["Dockerfile"].decode().splitlines() if line.startswith("COPY ")
                  for name in line.split()[1:-1]]
        self.assertEqual(len(copied), len(policy.IMAGE_FILES))
        self.assertEqual(set(copied), set(policy.IMAGE_FILES))

    def test_startup_user_mount_copy_or_other_build_changes_require_review(self):
        for suffix in (b"\nUSER root\n", b"\nENV EXTRA=changed\n", b"\nCOPY extra.py /app/\n",
                       b"\nENTRYPOINT [\"other\"]\n", b"\nRUN echo changed\n"):
            candidate = dict(self.inputs, Dockerfile=self.inputs["Dockerfile"] + suffix)
            with self.subTest(suffix=suffix), self.assertRaises(policy.DependencyReviewRequired):
                policy.compare(candidate, self.inputs)

    def test_python_family_or_distro_changes_require_review(self):
        for family in (b"python:3.13-slim-bookworm", b"python:3.12-slim-trixie", b"other:3.12-slim-bookworm"):
            candidate = dict(self.inputs, Dockerfile=self.inputs["Dockerfile"].replace(policy.BASE.encode(), family))
            with self.subTest(family=family), self.assertRaises(policy.DependencyReviewRequired):
                policy.compare(candidate, self.inputs)

    def test_old_release_can_bootstrap_only_the_approved_package_upgrade_step(self):
        before = self.inputs["Dockerfile"].decode().replace(policy.NEW_APT, policy.OLD_APT, 1).encode()
        self.assertNotEqual(before, self.inputs["Dockerfile"])
        policy.compare(self.inputs, dict(self.inputs, Dockerfile=before))
        changed = dict(self.inputs, **{"guard.py": b"changed controller"})
        with self.assertRaises(policy.DependencyReviewRequired):
            policy.compare(changed, dict(self.inputs, Dockerfile=before))

    def test_removing_package_upgrade_step_is_never_normalized_away(self):
        candidate = dict(self.inputs, Dockerfile=self.inputs["Dockerfile"].decode().replace(
            policy.NEW_APT, policy.OLD_APT, 1).encode())
        with self.assertRaises(policy.DependencyReviewRequired):
            policy.compare(candidate, self.inputs)

    def test_actual_render_cli_changes_only_temporary_from_digest(self):
        with tempfile.TemporaryDirectory() as folder:
            output = Path(folder) / "Dockerfile"
            source = self.root / "Dockerfile"
            before = source.read_bytes()
            result = subprocess.run([sys.executable, str(self.root / "tools/dependency_release.py"),
                "render", "--source", str(source), "--digest", "sha256:" + "a" * 64,
                "--output", str(output)], capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertEqual(source.read_bytes(), before)
            self.assertTrue(output.read_text().startswith("FROM " + policy.BASE + "@sha256:" + "a" * 64 + "\n"))
            self.assertEqual(output.read_text().splitlines()[1:], before.decode().splitlines()[1:])

    def test_image_hash_script_reads_all_payload_files_without_importing_guard(self):
        script = policy.image_script()
        self.assertIn("Path('/app')", script)
        for name in policy.IMAGE_FILES:
            self.assertIn(repr(name), script)
        self.assertNotIn("import guard", script)
        self.assertNotIn("connections.json", script)

    def test_build_order_blocks_old_repeated_and_incomplete_evidence(self):
        policy.newer_build("101", "1", "100", "1")
        policy.newer_build("100", "2", "100", "1")
        policy.newer_build("100", "1", "", "")
        for values in (("100", "1", "100", "1"), ("99", "9", "100", "1"),
                       ("100", "1", "", "1"), ("100", "1", "100", ""), ("bad", "1", "", "")):
            with self.subTest(values=values), self.assertRaises(policy.DependencyReviewRequired):
                policy.newer_build(*values)

    def test_automatic_workflow_is_main_only_after_success_and_serialized_with_manual_release(self):
        text = (self.root / ".github/workflows/release-dependencies.yml").read_text()
        for value in ("workflow_run:", "workflows: [Container]", "types: [completed]",
                      "head_branch == 'main'", "conclusion == 'success'",
                      "group: reviewed-image-promotion", "fetch-depth: 0", "persist-credentials: false"):
            self.assertIn(value, text)
        self.assertNotIn("ref: ${{ github.event.workflow_run", text)
        for check in ("tools/release_evidence.py candidate", "tools/dependency_release.py compare",
                      "tools/dependency_release.py newer", 'test "$NEW_CODE" = "$OLD_CODE"'):
            self.assertLess(text.index(check), text.index('docker tag "$IMAGE@$DIGEST"'))


if __name__ == "__main__":
    unittest.main()
