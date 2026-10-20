import contextlib
import io
import json
import os
import subprocess
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

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
        self.assertIsNone(worker.CHILD)

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
