"""Non-root container scheduler, dry-run by default."""

import argparse
import fcntl
import json
import math
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time

from authorization import (CONTAINER_SCOPE_FILE, RULE, ContainerAuthorization,
                           container_scope_record, read_container_scope)
from guard import GuardError, load_config, open_regular_file, source_policy_key
from safety import SafetyError, open_lock_file

CONFIG_DIR = Path("/config")
APP_DIR = Path(__file__).resolve().parent
INTERVAL_SECONDS = 600
CYCLE_TIMEOUT = 210
CYCLE_POLL_SECONDS = 0.25
TERMINATE_TIMEOUT = 2
KILL_TIMEOUT = 2
CONTAINER_LIVE_RELEASE_ENABLED = True  # The operator must still select live mode.
STOP = threading.Event()
CHILD = None


def runtime_config(env):
    def required(key):
        value = env.get(key)
        if not isinstance(value, str) or not value or len(value) > 16384:
            raise GuardError("container_configuration_invalid")
        return value
    qb_url = required("STGUARD_QBIT_URL")
    source_mode = env.get("STGUARD_SOURCE_POLICY")
    if source_mode is None:
        # Old templates keep their allowlist behavior; new installs need only
        # private exceptions. An explicit setting makes migration deliberate.
        source_mode = ("public_allowlist" if any("STGUARD_SONARR_" + quality + "_PUBLIC_INDEXERS" in env
                                               for quality in ("HD", "UHD")) else "private_exclusions")
    if source_mode not in ("public_allowlist", "private_exclusions"):
        raise GuardError("invalid_source_policy")
    result = {"dry_run": True, "minimum_age_seconds": 120, "max_torrents_per_run": 100,
              "max_pages": 20, "qbittorrent": {"url": qb_url,
                  "username": required("STGUARD_QBIT_USERNAME"), "password": required("STGUARD_QBIT_PASSWORD")},
              "sonarr": {}}
    for quality in ("HD", "UHD"):
        prefix = "STGUARD_SONARR_" + quality + "_"
        client_id = required(prefix + "CLIENT_ID")
        if not client_id.isascii() or not client_id.isdecimal() or int(client_id) <= 0:
            raise GuardError("container_configuration_invalid")
        lists = {"mode": source_mode, "private": json.loads(required(prefix + "PRIVATE_INDEXERS"))}
        if source_mode == "public_allowlist":
            lists["public"] = json.loads(required(prefix + "PUBLIC_INDEXERS"))
        result["sonarr"]["Sonarr-" + quality] = {
            "url": required(prefix + "URL"), "api_key": required(prefix + "API_KEY"),
            "category": required(prefix + "CATEGORY"), "indexers": lists,
            "download_client_binding": {"id": int(client_id), "endpoint": qb_url}}
    return result


def private_directory():
    if CONFIG_DIR.is_symlink() or not CONFIG_DIR.is_dir() or CONFIG_DIR.stat().st_uid != os.geteuid():
        raise GuardError("container_private_appdata_required")
    # Only this dedicated appdata mount, never a general media/share directory.
    CONFIG_DIR.chmod(0o700)


def atomic_json(path, value):
    if path.is_symlink():
        raise GuardError("container_private_appdata_required")
    temporary = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", dir=CONFIG_DIR, prefix=".guard-", delete=False) as output:
            temporary = Path(output.name)
            os.fchmod(output.fileno(), 0o600)
            json.dump(value, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None and temporary.exists():
            temporary.unlink()


def configure(env, *, check_only=False, validate=None):
    path = CONFIG_DIR / "connections.json"
    if path.is_symlink():
        raise GuardError("container_private_appdata_required")
    source = env.get("STGUARD_CONFIG_SOURCE", "env")
    if source == "env":
        candidate = runtime_config(env)
        # Validate privately before replacing an existing working configuration.
        temporary = CONFIG_DIR / ".connections-validation.json"
        try:
            atomic_json(temporary, candidate)
            candidate = load_config(temporary)
            if path.exists():
                previous = load_config(path)
                from production import binding_digest
                # Labels belong to the approved scope. Match
                # actual bindings, never HD/UHD ordering or the generated labels.
                preserved = {}
                for label in previous["sonarr"]:
                    matches = [name for name in candidate["sonarr"]
                               if binding_digest(candidate, name) == binding_digest(previous, label)]
                    if len(matches) != 1 or matches[0] in preserved.values():
                        raise GuardError("container_identity_migration_required")
                    prior_mode = source_policy_key(previous["sonarr"][label]["indexers"])["mode"]
                    next_mode = source_policy_key(candidate["sonarr"][matches[0]]["indexers"])["mode"]
                    if prior_mode != next_mode and env.get("STGUARD_SOURCE_POLICY") != next_mode:
                        raise GuardError("container_source_policy_migration_required")
                    preserved[label] = matches[0]
                if len(preserved) != len(candidate["sonarr"]):
                    raise GuardError("container_identity_migration_required")
                candidate["sonarr"] = {label: candidate["sonarr"][name] for label, name in preserved.items()}
        finally:
            if temporary.exists() and not temporary.is_symlink():
                temporary.unlink()
    elif source == "file":
        candidate = load_config(path)
    else:
        raise GuardError("container_configuration_invalid")
    if validate is not None:
        validate(candidate)
    if source == "env" and not check_only:
        atomic_json(path, candidate)
    return path


def healthcheck():
    try:
        with open_regular_file(CONFIG_DIR / "container-status.json", nofollow=True) as (file, _):
            status = json.load(file)
        stamp = status["updated_at"]
        return 0 if (not isinstance(stamp, bool) and isinstance(stamp, (int, float)) and math.isfinite(stamp)
                     and 0 <= time.time() - stamp <= INTERVAL_SECONDS + CYCLE_TIMEOUT + 90) else 1
    except Exception:
        return 1


def stop_worker(*unused):
    STOP.set()
    if CHILD is not None and CHILD.poll() is None:
        try:
            CHILD.terminate()
        except ProcessLookupError:
            pass  # Child exited between poll and terminate; run_cycle reaps it.


def terminate_child(child):
    try:
        child.terminate()
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=TERMINATE_TIMEOUT)
    except subprocess.TimeoutExpired:
        try:
            child.kill()
        except ProcessLookupError:
            pass
        child.wait(timeout=KILL_TIMEOUT)


def run_cycle(mode, path):
    global CHILD
    command = [sys.executable, str(APP_DIR / ("routine.py" if mode == "live" else "public.py")),
               "--config", str(path), "--log-file",
               str(CONFIG_DIR / ("routine.log" if mode == "live" else "dry-run.log"))]
    if mode == "live":
        command.extend(["--live", "--container-mode"])
    # Credentials are in the owner-private runtime config, not process arguments
    # or a child environment dump. No shell command construction.
    env = {key: value for key, value in os.environ.items() if key in
           ("PATH", "HOME", "TZ", "LANG", "LC_ALL", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE")}
    if mode == "live":
        env["STGUARD_MODE"] = "live"
    if STOP.is_set():
        return 143
    CHILD = subprocess.Popen(command, env=env)
    try:
        # A signal can arrive inside Popen before CHILD becomes visible to the
        # handler. Close that window before waiting or permitting another cycle.
        deadline = time.monotonic() + CYCLE_TIMEOUT
        while True:
            if STOP.is_set():
                terminate_child(CHILD)
                return 143
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                terminate_child(CHILD)
                return 124
            try:
                return CHILD.wait(timeout=min(CYCLE_POLL_SECONDS, remaining))
            except subprocess.TimeoutExpired:
                pass  # Recheck stop requests without resetting the cycle budget.
    finally:
        CHILD = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    action = parser.add_mutually_exclusive_group()
    action.add_argument("--check-config", action="store_true", help="Validate only; no API requests")
    action.add_argument("--approve-live-scope", action="store_true",
                        help="Confirm the current Docker cleanup scope and exit without API requests")
    action.add_argument("--once", action="store_true", help="Run a single cycle")
    action.add_argument("--healthcheck", action="store_true")
    args = parser.parse_args()
    if args.healthcheck:
        return healthcheck()
    try:
        os.umask(0o077)
        mode = os.environ.get("STGUARD_MODE", "dry-run")
        if mode not in ("dry-run", "live") or (mode == "live" and CONTAINER_LIVE_RELEASE_ENABLED is not True):
            raise GuardError("container_live_not_released_or_invalid_mode")
        private_directory()
        lock_path = CONFIG_DIR / "container-worker.lock"
        if lock_path.is_symlink():
            raise GuardError("container_private_appdata_required")
        with open_lock_file(lock_path) as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            fresh = all(entry.name == lock_path.name for entry in CONFIG_DIR.iterdir())
            scope_path = CONFIG_DIR / CONTAINER_SCOPE_FILE
            scope_update = {"rule": RULE, "scope_digest": None} if fresh else None

            def validate_scope(config):
                nonlocal scope_update
                if mode == "dry-run":
                    if args.approve_live_scope:
                        raise SafetyError("live_execution_disabled")
                    return
                if config.get("minimum_age_seconds", 120) < 120:
                    raise SafetyError("routine_authorization_expired_or_scope_changed")
                if scope_path.is_symlink():
                    raise SafetyError("container_live_scope_confirmation_required")
                expected = container_scope_record(config)
                if args.approve_live_scope or fresh:
                    scope_update = expected
                    return
                approved = read_container_scope(scope_path)
                if approved["scope_digest"] is None:
                    scope_update = expected
                elif approved != expected:
                    raise SafetyError("container_live_scope_confirmation_required")

            path = configure(os.environ, check_only=args.check_config, validate=validate_scope)
            if args.check_config:
                print(json.dumps({"event": "container_configuration_valid", "mode": mode, "actions_sent": False}))
                return 0
            if scope_update is not None:
                atomic_json(scope_path, scope_update)
            if args.approve_live_scope:
                print(json.dumps({"event": "container_live_scope_confirmed", "actions_sent": False}))
                return 0
            if mode == "live":
                ContainerAuthorization(load_config(path), path)
            signal.signal(signal.SIGTERM, stop_worker)
            signal.signal(signal.SIGINT, stop_worker)
            while not STOP.is_set():
                atomic_json(CONFIG_DIR / "container-status.json", {"updated_at": time.time(), "mode": mode, "stage": "running"})
                code = run_cycle(mode, path)
                if STOP.is_set():
                    # Do not start another appdata fsync while the array stops.
                    if args.once:
                        return code
                    break
                atomic_json(CONFIG_DIR / "container-status.json", {"updated_at": time.time(), "mode": mode, "stage": "waiting", "exit_code": code})
                print(json.dumps({"event": "container_cycle", "mode": mode, "exit_code": code}), flush=True)
                if args.once:
                    return code
                if STOP.wait(INTERVAL_SECONDS):
                    break
        return 0
    except BlockingIOError:
        reason = "another_container_worker_is_active"
    except (SafetyError, GuardError) as error:
        allowed = {"duplicate_sonarr_endpoint", "container_live_scope_confirmation_required", "invalid_worker_lock"}
        reason = str(error) if str(error) in allowed else "container_configuration_or_startup_unavailable"
    except Exception:
        # Environment/config/HTTP exceptions can contain credentials: never print them.
        reason = "container_configuration_or_startup_unavailable"
    print(json.dumps({"event": "container_waiting", "reason": reason}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
