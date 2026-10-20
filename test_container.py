import contextlib
import io
import json
import os
import signal
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, call, patch

import container_worker as worker


def example_environment():
    result = {}
    for line in (Path(__file__).parent / "deploy/container.env.example").read_text().splitlines():
        if line and not line.startswith("#"):
            key, value = line.split("=", 1)
            result[key] = value
    return result


class ContainerTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory()
        self.addCleanup(self.folder.cleanup)
        self.path = Path(self.folder.name)
        self.path.chmod(0o700)
        patcher = patch.object(worker, "CONFIG_DIR", self.path)
        patcher.start(); self.addCleanup(patcher.stop)
        patcher = patch.object(worker, "STOP", threading.Event())
        patcher.start(); self.addCleanup(patcher.stop)
        self.env = example_environment()

    def test_environment_builds_both_owners_with_explicit_source_lists(self):
        config = worker.runtime_config(self.env)
        self.assertTrue(config["dry_run"])
        self.assertEqual(set(config["sonarr"]), {"Sonarr-HD", "Sonarr-UHD"})
        self.assertEqual(config["sonarr"]["Sonarr-HD"]["download_client_binding"]["endpoint"], self.env["STGUARD_QBIT_URL"])
        path = worker.configure(self.env)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text()), config)

    def test_invalid_env_does_not_replace_existing_configuration(self):
        path = worker.configure(self.env)
        before = path.read_bytes()
        for changes in ({"STGUARD_QBIT_PASSWORD": ""}, {"STGUARD_SONARR_HD_CLIENT_ID": "true"},
                        {"STGUARD_SONARR_HD_PUBLIC_INDEXERS": "not-json"},
                        {"STGUARD_SONARR_UHD_CATEGORY": "tv-hd"}):
            with self.subTest(changes=list(changes)), self.assertRaises(Exception):
                worker.configure(dict(self.env, **changes))
            self.assertEqual(path.read_bytes(), before)

    def test_file_configuration_is_not_overwritten_by_environment(self):
        path = worker.configure(self.env)
        before = path.read_bytes()
        self.assertEqual(worker.configure({"STGUARD_CONFIG_SOURCE": "file"}), path)
        self.assertEqual(path.read_bytes(), before)

    def legacy_hold(self):
        import production
        from safety import Journal
        from test_production import ProductionTests
        fixture = ProductionTests()
        fixture.setUp()
        def cleanup():
            fixture.tearDown()
            fixture.doCleanups()
        self.addCleanup(cleanup)
        config = worker.runtime_config(self.env)
        config["sonarr"] = {quality: config["sonarr"]["Sonarr-" + quality] for quality in ("HD", "UHD")}
        worker.atomic_json(self.path / "connections.json", config)
        context = dict(fixture.context, binding_digest=production.binding_digest(config, "HD"))
        journal = Journal(self.path / "action-journal.sqlite3", allow_single_test=True)
        row = journal.prepare(fixture.report, mode="single_test", context=context)
        journal.transition(row["key"], "prepared", "dispatch_recorded")
        journal.transition(row["key"], "dispatch_recorded", "manual_review")
        journal.close()
        return config, fixture.report

    def test_environment_preserves_legacy_labels_and_unresolved_hold_after_restart(self):
        import production
        from safety import Journal, SafetyError
        config, report = self.legacy_hold()
        journal_path = self.path / "action-journal.sqlite3"
        before = journal_path.read_bytes()
        for _ in range(2):
            current = json.loads(worker.configure(dict(self.env, STGUARD_QBIT_PASSWORD="rotated-placeholder")).read_text())
            self.assertEqual(set(current["sonarr"]), {"HD", "UHD"})
            self.assertEqual(current["sonarr"], config["sonarr"])
            journal = Journal(journal_path, read_only=True)
            try:
                with self.assertRaisesRegex(SafetyError, "previous_attempt_unresolved"):
                    production.check_prior_attempts(journal, report, config=current)
            finally:
                journal.close()
        self.assertEqual(journal_path.read_bytes(), before)

    def test_binding_changes_and_orphaned_appdata_require_explicit_migration(self):
        self.legacy_hold()
        path = self.path / "connections.json"
        before = path.read_bytes()
        for changes in ({"STGUARD_SONARR_HD_URL": "https://different.example.invalid"},
                        {"STGUARD_SONARR_HD_CLIENT_ID": "99"},
                        {"STGUARD_SONARR_HD_CATEGORY": "different"},
                        {"STGUARD_QBIT_URL": "https://different.example.invalid"}):
            with self.subTest(changes=list(changes)), self.assertRaisesRegex(Exception, "identity_migration_required"):
                worker.configure(dict(self.env, **changes))
            self.assertEqual(path.read_bytes(), before)
        path.unlink()
        with self.assertRaisesRegex(Exception, "identity_migration_required"):
            worker.configure(self.env)
        self.assertFalse(path.exists())

    def test_file_mode_cannot_hide_old_labels_or_change_recorded_binding(self):
        self.legacy_hold()
        path = self.path / "connections.json"
        for candidate in (worker.runtime_config(self.env),
                          dict(json.loads(path.read_text()), qbittorrent={"url": "https://different.example.invalid",
                               "username": "REPLACE_ME", "password": "REPLACE_ME"})):
            # Keep config structurally valid so the journal comparison is tested.
            for item in candidate["sonarr"].values():
                item["download_client_binding"]["endpoint"] = candidate["qbittorrent"]["url"]
            worker.atomic_json(path, candidate)
            with self.assertRaisesRegex(Exception, "identity_migration_required"):
                worker.configure({"STGUARD_CONFIG_SOURCE": "file"})

    def test_orphaned_journal_requires_original_config_even_when_empty(self):
        from safety import Journal
        journal = Journal(self.path / "action-journal.sqlite3")
        journal.close()
        before = (self.path / "action-journal.sqlite3").read_bytes()
        with self.assertRaisesRegex(Exception, "identity_migration_required"):
            worker.configure(self.env)
        self.assertFalse((self.path / "connections.json").exists())
        self.assertEqual((self.path / "action-journal.sqlite3").read_bytes(), before)

    def test_check_config_sends_no_requests_and_does_not_print_credentials(self):
        output = io.StringIO()
        env = dict(self.env, STGUARD_QBIT_PASSWORD="private-marker")
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["container_worker.py", "--check-config"]), \
                patch.object(worker, "run_cycle") as cycle, contextlib.redirect_stdout(output):
            self.assertEqual(worker.main(), 0)
        cycle.assert_not_called()
        self.assertNotIn("private-marker", output.getvalue())
        self.assertIs(json.loads(output.getvalue())["actions_sent"], False)

    def test_live_and_invalid_modes_fail_before_configuration_or_api_work(self):
        for mode in ("live", "LIVE", "false", "unknown"):
            output = io.StringIO()
            with self.subTest(mode=mode), patch.dict(os.environ, {"STGUARD_MODE": mode}, clear=True), patch(
                    "sys.argv", ["container_worker.py", "--once"]), patch.object(worker, "configure") as configure, \
                    patch.object(worker, "run_cycle", return_value=0), patch("signal.signal"), \
                    contextlib.redirect_stderr(output):
                self.assertEqual(worker.main(), 1)
            configure.assert_not_called()
            self.assertNotIn(mode, output.getvalue())

    def test_dry_run_is_default_and_loop_waits_ten_minutes_after_cycle(self):
        env = dict(self.env); env.pop("STGUARD_MODE")
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["container_worker.py"]), patch(
                "signal.signal"), patch.object(worker, "run_cycle", return_value=0) as cycle, patch.object(
                worker.STOP, "wait", return_value=True) as wait, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(worker.main(), 0)
        self.assertEqual(cycle.call_args.args[0], "dry-run")
        wait.assert_called_once_with(600)

    def test_child_receives_no_credentials_or_secret_environment(self):
        process = Mock(); process.wait.return_value = 0
        with patch.dict(os.environ, {"STGUARD_QBIT_PASSWORD": "private-marker", "PATH": "/bin"}, clear=True), patch(
                "subprocess.Popen", return_value=process) as popen:
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 0)
        self.assertIn("public.py", popen.call_args.args[0][1])
        self.assertNotIn("private-marker", str(popen.call_args))
        process.wait.assert_called_once_with(timeout=210)

    def test_second_worker_on_same_appdata_fails_closed(self):
        import fcntl
        with open(self.path / "container-worker.lock", "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            with patch.dict(os.environ, self.env, clear=True), patch("sys.argv", ["container_worker.py", "--check-config"]), \
                    contextlib.redirect_stderr(io.StringIO()), patch.object(worker, "configure") as configure:
                self.assertEqual(worker.main(), 1)
            configure.assert_not_called()

    def test_stuck_child_is_terminated_then_killed_with_bounded_waits(self):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 210),
                                    subprocess.TimeoutExpired("worker", 10), -9]
        with patch("subprocess.Popen", return_value=process):
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 124)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_args_list, [call(timeout=210), call(timeout=10), call(timeout=10)])
        self.assertIsNone(worker.CHILD)

    def test_stop_before_launch_creates_no_child(self):
        worker.STOP.set()
        with patch("subprocess.Popen") as popen:
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 143)
        popen.assert_not_called()

    def test_real_signal_during_launch_terminates_and_reaps_new_child(self):
        original_popen = subprocess.Popen
        children = []
        def launch(*args, **kwargs):
            child = original_popen([sys.executable, "-c", "import time; time.sleep(60)"])
            children.append(child)
            os.kill(os.getpid(), signal.SIGTERM)
            return child
        previous = signal.signal(signal.SIGTERM, worker.stop_worker)
        try:
            with patch("subprocess.Popen", side_effect=launch):
                self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 143)
            self.assertIsNotNone(children[0].poll())
            self.assertIsNone(worker.CHILD)
        finally:
            signal.signal(signal.SIGTERM, previous)
            for child in children:
                if child.poll() is None:
                    child.kill()
                child.wait(timeout=10)

    def test_launch_race_with_term_ignoring_child_uses_bounded_kill_wait(self):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 10), -9]
        def launch(*args, **kwargs):
            worker.stop_worker()
            return process
        with patch("subprocess.Popen", side_effect=launch):
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 143)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_args_list, [call(timeout=10), call(timeout=10)])

    def test_stop_signal_interrupts_child_and_scheduler_wait(self):
        process = Mock(); process.poll.return_value = None
        with patch.object(worker, "CHILD", process):
            worker.stop_worker()
        process.terminate.assert_called_once()
        self.assertTrue(worker.STOP.is_set())

    def test_startup_error_does_not_disclose_environment_values(self):
        env = dict(self.env, STGUARD_SONARR_HD_PUBLIC_INDEXERS="private-marker")
        output = io.StringIO()
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["container_worker.py", "--check-config"]), \
                contextlib.redirect_stderr(output):
            self.assertEqual(worker.main(), 1)
        self.assertNotIn("private-marker", output.getvalue())

    def test_healthcheck_reports_stale_or_malformed_status(self):
        self.assertEqual(worker.healthcheck(), 1)
        worker.atomic_json(self.path / "container-status.json", {"updated_at": time.time()})
        self.assertEqual(worker.healthcheck(), 0)
        for stamp in (time.time() - 1000, True, "now", time.time() + 30):
            worker.atomic_json(self.path / "container-status.json", {"updated_at": stamp})
            self.assertEqual(worker.healthcheck(), 1)

    def test_explicit_docker_source_allowlist_excludes_private_runtime_files(self):
        root = Path(__file__).parent
        docker = (root / "Dockerfile").read_text()
        self.assertNotIn("COPY .", docker)
        self.assertIn("USER 1000:1000", docker)
        copied = next(line for line in docker.splitlines() if line.startswith("COPY ")).split()[1:-1]
        self.assertTrue(all(name.endswith(".py") and not name.startswith("test_") for name in copied))
        for name in ("connections.json", "routine-authorization.json", "HANDOFF.md", "config.example.json"):
            self.assertNotIn(name, copied)

    def test_container_control_code_is_bound_into_live_grant_digest(self):
        from authorization import SOURCE_FILES
        self.assertIn("container_worker.py", SOURCE_FILES)


if __name__ == "__main__":
    unittest.main()
