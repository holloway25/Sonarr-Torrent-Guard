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
    for line in (Path(__file__).resolve().parents[2] / "deploy/container.env.example").read_text().splitlines():
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

    def test_environment_builds_both_owners_with_private_exclusions_only(self):
        config = worker.runtime_config(self.env)
        self.assertTrue(config["dry_run"])
        self.assertEqual(set(config["sonarr"]), {"Sonarr-HD", "Sonarr-UHD"})
        self.assertEqual(config["sonarr"]["Sonarr-HD"]["indexers"]["mode"], "private_exclusions")
        self.assertNotIn("public", config["sonarr"]["Sonarr-HD"]["indexers"])
        self.assertEqual(config["sonarr"]["Sonarr-HD"]["download_client_binding"]["endpoint"], self.env["STGUARD_QBIT_URL"])
        path = worker.configure(self.env)
        self.assertEqual(path.stat().st_mode & 0o777, 0o600)
        self.assertEqual(json.loads(path.read_text()), config)

    def test_invalid_env_does_not_replace_existing_configuration(self):
        path = worker.configure(self.env)
        before = path.read_bytes()
        for changes in ({"STGUARD_QBIT_PASSWORD": ""}, {"STGUARD_SONARR_HD_CLIENT_ID": "true"},
                        {"STGUARD_SONARR_HD_PRIVATE_INDEXERS": "not-json"},
                        {"STGUARD_SOURCE_POLICY": "typo"},
                        {"STGUARD_SONARR_UHD_CATEGORY": "tv-hd"}):
            with self.subTest(changes=list(changes)), self.assertRaises(Exception):
                worker.configure(dict(self.env, **changes))
            self.assertEqual(path.read_bytes(), before)

    def test_file_configuration_is_not_overwritten_by_environment(self):
        path = worker.configure(self.env)
        before = path.read_bytes()
        self.assertEqual(worker.configure({"STGUARD_CONFIG_SOURCE": "file"}), path)
        self.assertEqual(path.read_bytes(), before)

    def test_legacy_environment_keeps_allowlists_without_explicit_new_policy(self):
        env = dict(self.env)
        env.pop("STGUARD_SOURCE_POLICY")
        for quality in ("HD", "UHD"):
            env["STGUARD_SONARR_" + quality + "_PUBLIC_INDEXERS"] = '["Public Source"]'
        config = worker.runtime_config(env)
        self.assertEqual(config["sonarr"]["Sonarr-HD"]["indexers"]["mode"], "public_allowlist")
        self.assertEqual(config["sonarr"]["Sonarr-HD"]["indexers"]["public"], ["Public Source"])

    def test_existing_allowlist_requires_explicit_policy_migration(self):
        path = worker.configure(self.env)
        prior = json.loads(path.read_text())
        for instance in prior["sonarr"].values():
            instance["indexers"].update(mode="public_allowlist", public=["Public Source"])
        worker.atomic_json(path, prior)
        before = path.read_bytes()
        env = dict(self.env); env.pop("STGUARD_SOURCE_POLICY")
        with self.assertRaisesRegex(Exception, "container_source_policy_migration_required"):
            worker.configure(env)
        self.assertEqual(path.read_bytes(), before)
        changed = json.loads(worker.configure(self.env).read_text())
        self.assertEqual(changed["sonarr"]["Sonarr-HD"]["indexers"]["mode"], "private_exclusions")

    def legacy_hold(self):
        import production
        from safety import Journal
        from tools.tests.test_production import ProductionTests
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

    def test_invalid_modes_fail_before_configuration_or_api_work(self):
        for mode in ("LIVE", "false", "unknown"):
            output = io.StringIO()
            with self.subTest(mode=mode), patch.dict(os.environ, {"STGUARD_MODE": mode}, clear=True), patch(
                    "sys.argv", ["container_worker.py", "--once"]), patch.object(worker, "configure") as configure, \
                    patch.object(worker, "run_cycle", return_value=0), patch("signal.signal"), \
                    contextlib.redirect_stderr(output):
                self.assertEqual(worker.main(), 1)
            configure.assert_not_called()
            self.assertNotIn(mode, output.getvalue())

    def test_live_mode_without_grant_cannot_start_a_cycle(self):
        env = dict(self.env, STGUARD_MODE="live")
        with patch.dict(os.environ, env, clear=True), patch("sys.argv", ["container_worker.py", "--once"]), \
                patch.object(worker, "run_cycle") as cycle, contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(worker.main(), 1)
        cycle.assert_not_called()

    def test_live_mode_requires_exact_private_grant_even_for_config_check(self):
        import secrets
        from authorization import RULE, RoutineAuthorization, code_digest, scope_digest
        from safety import SafetyError
        env = dict(self.env, STGUARD_MODE="live")
        config = worker.runtime_config(env)
        grant = {"enabled": True, "rule": RULE, "grant_id": secrets.token_hex(32),
                 "issued_at": time.time() - 1, "expires_at": None, "authorization_mode": "ongoing",
                 "scope_digest": scope_digest(config), "code_digest": code_digest()}
        path = self.path / "routine-authorization.json"
        for changes, expected in (({}, 0), ({"enabled": False}, 1), ({"code_digest": "e" * 64}, 1),
                                  ({"scope_digest": "f" * 64}, 1)):
            worker.atomic_json(path, dict(grant, **changes))
            with self.subTest(changes=changes), patch.dict(os.environ, env, clear=True), patch(
                    "sys.argv", ["container_worker.py", "--check-config"]), patch.object(
                    worker, "run_cycle") as cycle, contextlib.redirect_stderr(io.StringIO()), \
                    contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(worker.main(), expected)
            cycle.assert_not_called()
        worker.atomic_json(path, grant)
        path.chmod(0o644)
        with self.assertRaises(SafetyError):
            RoutineAuthorization.load(path, config)

    def test_live_scheduler_invokes_granted_routine_with_no_embedded_secrets(self):
        process = Mock(); process.wait.return_value = 0
        with patch("subprocess.Popen", return_value=process) as popen:
            self.assertEqual(worker.run_cycle("live", self.path / "connections.json"), 0)
        args = popen.call_args.args[0]
        self.assertTrue(args[1].endswith("routine.py"))
        self.assertIn("--live", args)
        self.assertEqual(args[args.index("--authorization") + 1], str(self.path / "routine-authorization.json"))

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
        process.wait.assert_called_once_with(timeout=0.25)

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
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 0.25),
                                    subprocess.TimeoutExpired("worker", 2), -9]
        with patch("subprocess.Popen", return_value=process), patch.object(
                worker.time, "monotonic", side_effect=[0, 0, 210]):
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 124)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_args_list, [call(timeout=0.25), call(timeout=2), call(timeout=2)])
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
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 2), -9]
        def launch(*args, **kwargs):
            worker.stop_worker()
            return process
        with patch("subprocess.Popen", side_effect=launch):
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 143)
        process.terminate.assert_called_once()
        process.kill.assert_called_once()
        self.assertEqual(process.wait.call_args_list, [call(timeout=2), call(timeout=2)])

    def test_real_signal_while_waiting_kills_term_ignoring_child_promptly(self):
        original_popen = subprocess.Popen
        child = original_popen([sys.executable, "-c", "import signal,time; "
                               "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                               "print('ready', flush=True); time.sleep(60)"],
                               stdout=subprocess.PIPE, text=True)
        self.assertEqual(child.stdout.readline().strip(), "ready")
        waiting = threading.Event()
        original_wait = child.wait
        def active_wait(*args, **kwargs):
            waiting.set()
            return original_wait(*args, **kwargs)
        def request_stop():
            if waiting.wait(timeout=3):
                os.kill(os.getpid(), signal.SIGTERM)
        stopper = threading.Thread(target=request_stop)
        # A broken implementation must fail promptly, not hang this test for210s.
        watchdog = threading.Timer(6, lambda: child.kill() if child.poll() is None else None)
        previous = signal.signal(signal.SIGTERM, worker.stop_worker)
        try:
            stopper.start(); watchdog.start()
            started = time.monotonic()
            with patch("subprocess.Popen", return_value=child), patch.object(child, "wait", side_effect=active_wait):
                result = worker.run_cycle("dry-run", self.path / "connections.json")
            self.assertEqual(result, 143)
            self.assertLess(time.monotonic() - started, 5.5)
            self.assertEqual(child.poll(), -signal.SIGKILL)
            self.assertIsNone(worker.CHILD)
        finally:
            watchdog.cancel(); watchdog.join()
            stopper.join(timeout=4)
            signal.signal(signal.SIGTERM, previous)
            if child.poll() is None:
                child.kill()
            original_wait(timeout=2)
            child.stdout.close()

    def test_polling_keeps_original_deadline_and_uses_remaining_budget(self):
        process = Mock()
        process.wait.side_effect = [subprocess.TimeoutExpired("worker", 0.25),
                                   subprocess.TimeoutExpired("worker", 0.125), 0]
        with patch("subprocess.Popen", return_value=process), patch.object(
                worker.time, "monotonic", side_effect=[0, 0, 209.875, 210]):
            self.assertEqual(worker.run_cycle("dry-run", self.path / "connections.json"), 124)
        self.assertEqual(process.wait.call_args_list, [call(timeout=0.25), call(timeout=0.125), call(timeout=2)])
        process.terminate.assert_called_once()
        process.kill.assert_not_called()

    def test_stopping_skips_final_heartbeat_write_and_next_cycle(self):
        def cycle(*args):
            worker.STOP.set()
            return 143
        with patch.dict(os.environ, self.env, clear=True), patch("sys.argv", ["container_worker.py"]), patch(
                "signal.signal"), patch.object(worker, "run_cycle", side_effect=cycle) as run, patch.object(
                worker, "atomic_json", wraps=worker.atomic_json) as write:
            self.assertEqual(worker.main(), 0)
        self.assertEqual(run.call_count, 1)
        status_writes = [c for c in write.call_args_list if c.args[0].name == "container-status.json"]
        self.assertEqual(len(status_writes), 1)
        self.assertEqual(status_writes[0].args[1]["stage"], "running")

    def test_stop_signal_interrupts_child_and_scheduler_wait(self):
        process = Mock(); process.poll.return_value = None
        with patch.object(worker, "CHILD", process):
            worker.stop_worker()
        process.terminate.assert_called_once()
        self.assertTrue(worker.STOP.is_set())

    def test_startup_error_does_not_disclose_environment_values(self):
        env = dict(self.env, STGUARD_SONARR_HD_PRIVATE_INDEXERS="private-marker")
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
        root = Path(__file__).resolve().parents[2]
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

    def test_image_distributes_gplv3_license_and_matching_source_metadata(self):
        root = Path(__file__).resolve().parents[2]
        license_text = (root / "LICENSE").read_text()
        self.assertIn("GNU GENERAL PUBLIC LICENSE", license_text)
        self.assertIn("Version 3, 29 June 2007", license_text)
        self.assertGreater(len(license_text), 30000)
        docker = (root / "Dockerfile").read_text()
        self.assertIn("COPY LICENSE /app/LICENSE", docker)
        self.assertIn('org.opencontainers.image.licenses="GPL-3.0-only"', docker)
        self.assertIn("!LICENSE", (root / ".dockerignore").read_text().splitlines())
        workflow = (root / ".github/workflows/container.yml").read_text()
        self.assertIn("org.opencontainers.image.source=https://github.com/${GITHUB_REPOSITORY}", workflow)
        self.assertIn("org.opencontainers.image.revision=${GITHUB_SHA}", workflow)

    def test_all_regression_modules_live_under_tools_and_ci_uses_discovery(self):
        root = Path(__file__).resolve().parents[2]
        self.assertEqual(list(root.glob("test_*.py")), [])
        self.assertGreaterEqual(len(list((root / "tools/tests").glob("test_*.py"))), 9)
        self.assertTrue((root / "tools/tests/__init__.py").is_file())
        for name in ("checks.yml", "container.yml"):
            workflow = (root / ".github/workflows" / name).read_text()
            self.assertIn("-m unittest discover -s tools/tests -t .", workflow)

    def test_unraid_template_defaults_match_supported_environment(self):
        import xml.etree.ElementTree as ET
        root = ET.parse(Path(__file__).resolve().parents[2] / "deploy/unraid.xml").getroot()
        entries = [item for item in root.findall("Config") if item.get("Type") == "Variable"]
        env = {item.get("Target"): item.get("Default") for item in entries}
        self.assertEqual(len(entries), len(env))
        self.assertEqual(set(env), set(example_environment()))
        self.assertEqual(env["STGUARD_MODE"], "dry-run")
        self.assertEqual(env["TZ"], "Australia/Melbourne")
        self.assertTrue(worker.runtime_config(env)["dry_run"])
        for item in entries:
            if any(x in item.get("Target") for x in ("API_KEY", "PASSWORD", "USERNAME")):
                self.assertEqual(item.get("Mask"), "true")
                self.assertEqual(item.get("Default"), "REPLACE_ME")

    def test_unraid_template_limits_mounts_privilege_and_shutdown(self):
        import xml.etree.ElementTree as ET
        root = ET.parse(Path(__file__).resolve().parents[2] / "deploy/unraid.xml").getroot()
        self.assertEqual(root.findtext("Network"), "bridge")
        self.assertEqual(root.findtext("Privileged"), "false")
        self.assertEqual(root.findtext("Name"), "sonarr-torrent-guard")
        self.assertFalse(root.findtext("WebUI"))
        paths = [item for item in root.findall("Config") if item.get("Type") == "Path"]
        self.assertEqual(len(paths), 1)
        self.assertEqual(paths[0].get("Target"), "/config")
        self.assertTrue(paths[0].get("Default").endswith("/sonarr-torrent-guard"))
        self.assertFalse(any(item.get("Type") == "Port" for item in root.findall("Config")))
        extra = root.findtext("ExtraParams").split()
        for flag in ("--user=1000:1000", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                     "--stop-timeout=10", "--log-opt=max-size=10m", "--log-opt=max-file=3"):
            self.assertIn(flag, extra)
        self.assertNotIn("--privileged", extra)
        self.assertRegex(root.findtext("Repository"), r"@sha256:[a-f0-9]{64}$")

    def test_unraid_template_references_approved_transparent_icon(self):
        import xml.etree.ElementTree as ET
        root = Path(__file__).resolve().parents[2]
        template = ET.parse(root / "deploy/unraid.xml").getroot()
        icon = "assets/sonarr-torrent-guard-darker.png"
        self.assertTrue(template.findtext("Icon").endswith("/" + icon))
        data = (root / icon).read_bytes()
        self.assertEqual(data[:8], b"\x89PNG\r\n\x1a\n")
        self.assertEqual(data[12:16], b"IHDR")
        self.assertEqual(data[25], 6)  # RGBA, preserving transparency.
        self.assertEqual(data[16:20], data[20:24])  # Square icon.


if __name__ == "__main__":
    unittest.main()
