import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
import zipfile

from tools.release_evidence import (EvidenceError, select_artifact, validate_record,
                                    validate_run, verify_archive)


class ReleaseEvidenceTests(unittest.TestCase):
    def setUp(self):
        self.repo = "example/sonarr-torrent-guard"
        self.digest = "sha256:" + "a" * 64
        self.run = {"id": 1001, "run_attempt": 1, "status": "completed", "conclusion": "success",
                    "path": ".github/workflows/container.yml", "event": "workflow_dispatch",
                    "head_repository": {"full_name": self.repo}, "head_sha": "b" * 40}
        self.record = {"schema": 1, "repository": self.repo, "run_id": 1001, "run_attempt": 1,
                       "revision": "b" * 40, "digest": self.digest, "image": "ghcr.io/" + self.repo,
                       "tag": "sha-" + "b" * 40 + "-run-1001-1"}
        self.artifact = {"id": 2001, "name": "publication-1001-1", "expired": False,
                         "digest": "sha256:" + "c" * 64,
                         "workflow_run": {"id": 1001, "head_sha": "b" * 40}}
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)

    def validate(self, record=None, run=None, digest=None):
        return validate_record(record if record is not None else self.record,
                               run if run is not None else self.run, self.repo, 1001,
                               digest if digest is not None else self.digest)

    def archive(self, contents=None, name="publication.json"):
        path = self.path / "publication.zip"
        with zipfile.ZipFile(path, "w") as output:
            output.writestr(name, contents if contents is not None else json.dumps(self.record))
        return path, "sha256:" + hashlib.sha256(path.read_bytes()).hexdigest()

    def test_exact_published_digest_is_accepted_for_manual_and_scheduled_runs(self):
        for event in ("workflow_dispatch", "schedule"):
            self.assertEqual(self.validate(run=dict(self.run, event=event)), self.record)

    def test_same_revision_different_build_digest_is_refused(self):
        # Both builds have the same source label: only publication evidence differs.
        other_digest = "sha256:" + "d" * 64
        with self.assertRaises(EvidenceError):
            self.validate(digest=other_digest)
        with self.assertRaises(EvidenceError):
            self.validate(record=dict(self.record, digest=other_digest))

    def test_wrong_run_attempt_revision_repository_image_or_tag_is_refused(self):
        for changes in ({"run_id": 1002}, {"run_attempt": 2}, {"revision": "e" * 40},
                        {"repository": "other/project"}, {"image": "ghcr.io/other/project"},
                        {"tag": "latest"}, {"schema": True}, {"run_id": True}):
            with self.subTest(changes=changes), self.assertRaises(EvidenceError):
                self.validate(record=dict(self.record, **changes))

    def test_missing_extra_or_malformed_record_fields_fail_closed(self):
        for key in self.record:
            value = dict(self.record); del value[key]
            with self.subTest(missing=key), self.assertRaises(EvidenceError):
                self.validate(record=value)
        for value in ([], {}, dict(self.record, extra=True), dict(self.record, digest="invalid")):
            with self.subTest(value=type(value).__name__), self.assertRaises(EvidenceError):
                self.validate(record=value)

    def test_unsuccessful_wrong_workflow_foreign_or_untrusted_run_is_refused(self):
        for changes in ({"status": "in_progress"}, {"conclusion": "failure"}, {"conclusion": "cancelled"},
                        {"path": ".github/workflows/other.yml"}, {"event": "pull_request"}, {"event": "push"},
                        {"head_repository": None}, {"head_repository": {"full_name": "other/project"}},
                        {"run_attempt": True}, {"run_attempt": 0}, {"head_sha": None}, {"id": 1002}):
            with self.subTest(changes=changes), self.assertRaises(EvidenceError):
                validate_run(dict(self.run, **changes), self.repo, 1001)

    def test_one_current_attempt_artifact_is_selected_across_pages(self):
        old = dict(self.artifact, name="publication-1001-0")
        result = select_artifact([{"artifacts": [old]}, {"artifacts": [self.artifact]}], self.run, self.repo, 1001)
        self.assertEqual(result, {"id": 2001, "digest": self.artifact["digest"]})

    def test_absent_duplicate_expired_wrong_attempt_or_foreign_artifacts_refused(self):
        for items in ([], [self.artifact, self.artifact], [dict(self.artifact, expired=True)],
                      [dict(self.artifact, name="publication-1001-0")],
                      [dict(self.artifact, digest=None)],
                      [dict(self.artifact, workflow_run={"id": 1002, "head_sha": "b" * 40})]):
            with self.subTest(items=len(items)), self.assertRaises(EvidenceError):
                select_artifact([{"artifacts": items}], self.run, self.repo, 1001)

    def test_artifact_hash_and_exact_record_verified_before_registry_access(self):
        path, digest = self.archive()
        self.assertEqual(verify_archive(path, digest, self.run, self.repo, 1001, self.digest), self.record)
        with self.assertRaises(EvidenceError):
            verify_archive(path, "sha256:" + "f" * 64, self.run, self.repo, 1001, self.digest)
        with self.assertRaises(EvidenceError):
            verify_archive(path, digest, self.run, self.repo, 1001, "sha256:" + "d" * 64)

    def test_untrusted_zip_paths_are_never_extracted_or_executed(self):
        path, digest = self.archive(name="../publication.json")
        with self.assertRaises(EvidenceError):
            verify_archive(path, digest, self.run, self.repo, 1001, self.digest)
        self.assertEqual(list(self.path.iterdir()), [path])

    def test_duplicate_json_keys_are_refused_for_otherwise_valid_record(self):
        original = json.dumps(self.record)
        for key, value in self.record.items():
            content = "{" + json.dumps(key) + ":" + json.dumps(value) + "," + original[1:]
            # Without duplicate-key rejection this exact fixture is fully valid.
            self.assertEqual(json.loads(content), self.record)
            self.validate(record=json.loads(content))
            path, digest = self.archive(contents=content)
            with self.subTest(key=key), self.assertRaises(EvidenceError):
                verify_archive(path, digest, self.run, self.repo, 1001, self.digest)

    def test_large_publication_records_are_refused(self):
        path, digest = self.archive(contents=" " * 16385)
        with self.assertRaises(EvidenceError):
            verify_archive(path, digest, self.run, self.repo, 1001, self.digest)

    def test_actual_record_cli_creates_only_expected_metadata(self):
        tool = Path(__file__).resolve().parents[1] / "release_evidence.py"
        output = self.path / "publication.json"
        env = dict(os.environ, GITHUB_REPOSITORY=self.repo, GITHUB_SHA="b" * 40,
                   GITHUB_RUN_ID="1001", GITHUB_RUN_ATTEMPT="1")
        result = subprocess.run([sys.executable, str(tool), "record", "--digest", self.digest,
                                 "--output", str(output)], env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(output.read_text()), self.record)
        self.validate(record=json.loads(output.read_text()))

    def test_actual_verify_cli_refuses_other_digest_at_same_commit(self):
        tool = Path(__file__).resolve().parents[1] / "release_evidence.py"
        path, digest = self.archive()
        run = self.path / "run.json"
        run.write_text(json.dumps(self.run))
        args = [sys.executable, str(tool), "verify", "--run", str(run), "--repository", self.repo,
                "--run-id", "1001", "--archive", str(path), "--archive-digest", digest, "--digest"]
        for candidate, expected in ((self.digest, 0), ("sha256:" + "d" * 64, 1)):
            result = subprocess.run(args + [candidate], capture_output=True, text=True)
            self.assertEqual(result.returncode, expected, result.stdout)

    def test_build_publishes_candidates_only_and_dependency_updates_are_proposals(self):
        root = Path(__file__).resolve().parents[2]
        dependabot = (root / ".github/dependabot.yml").read_text()
        for value in ("package-ecosystem: docker", "package-ecosystem: github-actions", "interval: daily"):
            self.assertIn(value, dependabot)
        workflow = (root / ".github/workflows/container.yml").read_text()
        self.assertIn("  schedule:", workflow)
        self.assertIn("--pull --no-cache", workflow)
        self.assertIn("github.event_name == 'schedule'", workflow)
        self.assertIn("tools/release_evidence.py record", workflow)
        self.assertIn("actions/upload-artifact@", workflow)
        self.assertIn("${GITHUB_RUN_ID}-${GITHUB_RUN_ATTEMPT}", workflow)
        self.assertNotIn(":latest", workflow)
        self.assertNotIn("auto-merge", dependabot)
        self.assertIn("apt-get upgrade -y", (root / "Dockerfile").read_text())

    def test_actual_candidate_cli_selects_only_verified_publication_digest(self):
        tool = Path(__file__).resolve().parents[1] / "release_evidence.py"
        path, digest = self.archive()
        run = self.path / "run.json"
        run.write_text(json.dumps(self.run))
        args = [sys.executable, str(tool), "candidate", "--run", str(run), "--repository", self.repo,
                "--run-id", "1001", "--archive", str(path), "--archive-digest"]
        result = subprocess.run(args + [digest], capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertEqual(json.loads(result.stdout), self.record)
        result = subprocess.run(args + ["sha256:" + "f" * 64], capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
