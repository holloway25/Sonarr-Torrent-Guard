import hashlib
import json
import datetime
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
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
        for family in (b"python:3.12-slim-bookworm", b"python:3.14-slim-bookworm",
                       b"python:3.16-slim-bookworm", b"python:3.15-slim-trixie", b"other:3.15-slim-bookworm"):
            candidate = dict(self.inputs, Dockerfile=self.inputs["Dockerfile"].replace(policy.BASE.encode(), family))
            with self.subTest(family=family), self.assertRaises(policy.DependencyReviewRequired):
                policy.compare(candidate, self.inputs)

    def test_previous_python_family_requires_reviewed_migration(self):
        old = dict(self.inputs, Dockerfile=self.inputs["Dockerfile"].replace(
            policy.BASE.encode(), b"python:3.12-slim-bookworm", 1))
        with self.assertRaisesRegex(policy.DependencyReviewRequired, "base_family_change_requires_review"):
            policy.compare(self.inputs, old)

    def test_workflows_and_pinned_recipe_target_approved_python_family(self):
        self.assertEqual(policy.BASE, "python:3.15-slim-bookworm")
        self.assertRegex(self.inputs["Dockerfile"].decode(),
                         r"\AFROM python:3\.15-slim-bookworm@sha256:[a-f0-9]{64}\n")
        checks = (self.root / ".github/workflows/checks.yml").read_text()
        self.assertIn("python-version: '3.15'", checks)
        container = (self.root / ".github/workflows/container.yml").read_text()
        self.assertIn("docker pull " + policy.BASE, container)
        self.assertEqual(container.count("assert sys.version_info[:2] == (3, 15)"), 2)
        release = (self.root / ".github/workflows/release-dependencies.yml").read_text()
        self.assertIn("= " + policy.BASE, release)

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

    def test_generated_image_script_hashes_actual_fixture_contents(self):
        # Redirect only the container's /app root; execute the generated script
        # unchanged in a fresh process, without needing Docker or a host /app.
        runner = """
import sys
from pathlib import Path
from unittest.mock import patch
root = Path(sys.argv[1])
def fixture_path(value):
    if value != '/app':
        raise AssertionError('unexpected_image_path')
    return root
with patch('pathlib.Path', side_effect=fixture_path):
    exec(compile(sys.argv[2], '<generated-image-script>', 'exec'))
"""
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixtures = {name: ("raise RuntimeError('payload must not execute: " + name + "')\n").encode()
                        for name in policy.IMAGE_FILES}
            for name, content in fixtures.items():
                (root / name).write_bytes(content)

            def fingerprint():
                return subprocess.run([sys.executable, "-c", runner, str(root), policy.image_script()],
                                      capture_output=True, text=True, timeout=10)

            baseline = fingerprint()
            self.assertEqual(baseline.returncode, 0, baseline.stderr)
            expected = hashlib.sha256(json.dumps(
                {name: hashlib.sha256(content).hexdigest() for name, content in fixtures.items()},
                sort_keys=True).encode()).hexdigest()
            self.assertEqual(baseline.stdout.strip(), expected)
            self.assertEqual(fingerprint().stdout, baseline.stdout)
            for name, content in fixtures.items():
                with self.subTest(changed=name):
                    (root / name).write_bytes(content + b"changed fixture bytes\n")
                    changed = fingerprint()
                    self.assertEqual(changed.returncode, 0, changed.stderr)
                    self.assertRegex(changed.stdout.strip(), r"\A[a-f0-9]{64}\Z")
                    self.assertNotEqual(changed.stdout, baseline.stdout)
                    (root / name).write_bytes(content)
                with self.subTest(missing=name):
                    (root / name).unlink()
                    missing = fingerprint()
                    self.assertNotEqual(missing.returncode, 0)
                    self.assertEqual(missing.stdout, "")
                    (root / name).write_bytes(content)

    def test_build_order_blocks_old_repeated_and_incomplete_evidence(self):
        policy.newer_build("101", "1", "100", "1")
        policy.newer_build("100", "2", "100", "1")
        policy.newer_build("100", "1", "", "")
        for values in (("100", "1", "100", "1"), ("99", "9", "100", "1"),
                       ("100", "1", "", "1"), ("100", "1", "100", ""), ("bad", "1", "", "")):
            with self.subTest(values=values), self.assertRaises(policy.DependencyReviewRequired):
                policy.newer_build(*values)

    def test_image_maintenance_is_gated_and_dependency_pr_checks_stay_weekly(self):
        workflow = (self.root / ".github/workflows/container.yml").read_text()
        schedules = [line.strip() for line in workflow.splitlines() if line.strip().startswith("- cron:")]
        self.assertEqual(schedules, ["- cron: '17 23 * * *'"])
        self.assertIn("    needs: cadence\n    if: needs.cadence.outputs.run_build == 'true'", workflow)
        self.assertIn("run_build: ${{ steps.cadence.outputs.run_build }}", workflow)
        dependabot = (self.root / ".github/dependabot.yml").read_text()
        for ecosystem in ("docker", "github-actions"):
            block = dependabot.split("- package-ecosystem: " + ecosystem + "\n", 1)[1].split(
                "- package-ecosystem:", 1)[0]
            with self.subTest(ecosystem=ecosystem):
                self.assertIn("interval: weekly", block)
                self.assertIn("day: monday", block)
                self.assertIn("timezone: Australia/Melbourne", block)
                self.assertNotIn("interval: daily", block)

    def test_actual_cadence_script_runs_every_48_hours_across_calendar_boundaries(self):
        workflow = (self.root / ".github/workflows/container.yml").read_text()
        match = re.search(r"      - name: Decide maintenance cadence\n"
                          r"        id: cadence\n        run: \|\n((?:          [^\n]*\n)+)", workflow)
        self.assertIsNotNone(match)
        script = textwrap.dedent(match.group(1))
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            output = root / "output"

            def run(event, stamp, clock='date() { printf "%s\\n" "$TEST_NOW"; }\n'):
                output.write_text("")
                env = dict(os.environ, GITHUB_EVENT_NAME=event, GITHUB_OUTPUT=str(output),
                           TEST_NOW=str(stamp))
                # A shell clock fixture needs no executable files on /tmp,
                # which is intentionally noexec in the hardened CI container.
                return subprocess.run(["bash", "-c", clock + script], env=env, capture_output=True,
                                      text=True, timeout=5)

            def due(event, stamp):
                result = run(event, stamp)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(result.stderr, "")
                value = output.read_text().strip()
                self.assertIn(value, ("run_build=true", "run_build=false"))
                return value == "run_build=true"

            starts = (datetime.date(2026, 10, 28), datetime.date(2026, 12, 28),
                      datetime.date(2027, 2, 25), datetime.date(2028, 2, 25))
            for start in starts:
                results = []
                for offset in range(8):
                    day = start + datetime.timedelta(days=offset)
                    stamp = int(datetime.datetime.combine(day, datetime.time(23, 17),
                                tzinfo=datetime.timezone.utc).timestamp())
                    with self.subTest(day=day):
                        result = due("schedule", stamp)
                        self.assertEqual(result, (stamp // 86400) % 2 == 0)
                        results.append(result)
                self.assertTrue(all(a != b for a, b in zip(results, results[1:])))
                self.assertEqual(sum(results), 4)
            for event in ("push", "pull_request", "workflow_dispatch"):
                for stamp in (86400, 172800):
                    with self.subTest(event=event, stamp=stamp):
                        self.assertTrue(due(event, stamp))
            failed_clock = run("schedule", 0, 'date() { return 1; }\n')
            self.assertNotEqual(failed_clock.returncode, 0)
            self.assertEqual(output.read_text(), "")

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

    def test_full_suite_runs_under_built_image_before_candidate_publication(self):
        text = (self.root / ".github/workflows/container.yml").read_text()
        command = '--entrypoint python3 "$IMAGE" -m unittest discover -s tools/tests -t .'
        self.assertIn(command, text)
        self.assertLess(text.index(command), text.index('docker push "$IMAGE"'))
        self.assertIn('source=$GITHUB_WORKSPACE,target=/src,readonly', text)


if __name__ == "__main__":
    unittest.main()
