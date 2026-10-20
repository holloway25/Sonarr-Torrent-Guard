"""Non-root container scheduler; dry-run by default, no automatic live grants."""

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

from guard import GuardError, load_config

CONFIG_DIR = Path("/config")
APP_DIR = Path(__file__).resolve().parent
INTERVAL_SECONDS = 600
CYCLE_TIMEOUT = 210
CONTAINER_LIVE_RELEASE_ENABLED = False  # Review and migration approval required.
STOP = threading.Event()
CHILD = None


def runtime_config(env):
    def required(key):
        value = env.get(key)
        if not isinstance(value, str) or not value or len(value) > 16384:
            raise GuardError("container_configuration_invalid")
        return value
    qb_url = required("STGUARD_QBIT_URL")
    result = {"dry_run": True, "minimum_age_seconds": 120, "max_torrents_per_run": 100,
              "max_pages": 20, "qbittorrent": {"url": qb_url,
                  "username": required("STGUARD_QBIT_USERNAME"), "password": required("STGUARD_QBIT_PASSWORD")},
              "sonarr": {}}
    for quality in ("HD", "UHD"):
        prefix = "STGUARD_SONARR_" + quality + "_"
        client_id = required(prefix + "CLIENT_ID")
        if not client_id.isascii() or not client_id.isdecimal() or int(client_id) <= 0:
            raise GuardError("container_configuration_invalid")
        lists = {kind: json.loads(required(prefix + kind.upper() + "_INDEXERS")) for kind in ("public", "private")}
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


def configure(env):
    path = CONFIG_DIR / "connections.json"
    source = env.get("STGUARD_CONFIG_SOURCE", "env")
    if source == "env":
        candidate = runtime_config(env)
        # Validate privately before replacing an existing working configuration.
        temporary = CONFIG_DIR / ".connections-validation.json"
        try:
            atomic_json(temporary, candidate)
            load_config(temporary)
            atomic_json(path, candidate)
        finally:
            if temporary.exists() and not temporary.is_symlink():
                temporary.unlink()
    elif source != "file":
        raise GuardError("container_configuration_invalid")
    if path.is_symlink() or path.stat().st_mode & 0o077:
        raise GuardError("container_private_appdata_required")
    load_config(path)
    return path


def healthcheck():
    try:
        status = json.loads((CONFIG_DIR / "container-status.json").read_text())
        stamp = status["updated_at"]
        return 0 if (not isinstance(stamp, bool) and isinstance(stamp, (int, float)) and math.isfinite(stamp)
                     and 0 <= time.time() - stamp <= INTERVAL_SECONDS + CYCLE_TIMEOUT + 90) else 1
    except Exception:
        return 1


def stop_worker(*unused):
    STOP.set()
    if CHILD is not None and CHILD.poll() is None:
        CHILD.terminate()


def run_cycle(mode, path):
    global CHILD
    command = [sys.executable, str(APP_DIR / ("routine.py" if mode == "live" else "public.py")),
               "--config", str(path)]
    if mode == "live":
        command.extend(["--live", "--authorization", str(CONFIG_DIR / "routine-authorization.json"),
                        "--log-file", str(CONFIG_DIR / "routine.log")])
    # Credentials are in the owner-private runtime config, not process arguments
    # or a child environment dump. No shell command construction.
    env = {key: value for key, value in os.environ.items() if key in
           ("PATH", "HOME", "TZ", "LANG", "LC_ALL", "PYTHONUNBUFFERED", "PYTHONDONTWRITEBYTECODE")}
    CHILD = subprocess.Popen(command, env=env)
    try:
        return CHILD.wait(timeout=CYCLE_TIMEOUT)
    except subprocess.TimeoutExpired:
        CHILD.terminate()
        try:
            CHILD.wait(timeout=10)
        except subprocess.TimeoutExpired:
            CHILD.kill()
            CHILD.wait()
        return 124
    finally:
        CHILD = None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-config", action="store_true", help="Validate only; no API requests")
    parser.add_argument("--once", action="store_true", help="Run a single cycle")
    parser.add_argument("--healthcheck", action="store_true")
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
        with open(lock_path, "a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            path = configure(os.environ)
            if args.check_config:
                print(json.dumps({"event": "container_configuration_valid", "mode": mode, "actions_sent": False}))
                return 0
            signal.signal(signal.SIGTERM, stop_worker)
            signal.signal(signal.SIGINT, stop_worker)
            while not STOP.is_set():
                atomic_json(CONFIG_DIR / "container-status.json", {"updated_at": time.time(), "mode": mode, "stage": "running"})
                code = run_cycle(mode, path)
                atomic_json(CONFIG_DIR / "container-status.json", {"updated_at": time.time(), "mode": mode, "stage": "waiting", "exit_code": code})
                print(json.dumps({"event": "container_cycle", "mode": mode, "exit_code": code}), flush=True)
                if args.once or STOP.wait(INTERVAL_SECONDS):
                    break
        return 0
    except BlockingIOError:
        reason = "another_container_worker_is_active"
    except Exception:
        # Environment/config/HTTP exceptions can contain credentials: never print them.
        reason = "container_configuration_or_startup_unavailable"
    print(json.dumps({"event": "container_waiting", "reason": reason}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
