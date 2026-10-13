"""Repository content checks. Never print matched sensitive values."""
import argparse
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys


def git(*args):
    return subprocess.check_output(["git", *args])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--all", action="store_true")
    args = parser.parse_args()
    names = (git("ls-files", "-z") if args.all else
             git("diff", "--cached", "--name-only", "--diff-filter=ACMR", "-z"))
    issues = []
    patterns = {
        "IPv4 address": r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])",
        "MAC address": r"(?i)\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b",
        "email address": r"[\w.+-]+@[\w.-]+\.[A-Za-z]{2,}",
        "personal path": r"(?i)(?:[a-z]:[\\/]Users[\\/]|/(?:home|Users)/)[^\s/\\]+",
        "private key": r"-----BEGIN (?:OPENSSH |RSA |EC )?PRIVATE KEY-----",
        "GitHub token": r"\b(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,})\b",
    }
    for raw in names.split(b"\0"):
        if not raw:
            continue
        name = raw.decode()
        parts = PurePosixPath(name).parts
        leaf = parts[-1].lower()
        if (leaf.startswith("handoff") or leaf in ("connections.json", "config.json", ".env")
                or leaf.endswith((".log", ".lock", ".zip"))
                or any(x in ("local", "downloads", "staging") for x in parts)):
            issues.append((name, "prohibited runtime or handoff artifact"))
        data = Path(name).read_bytes() if args.all else git("show", ":" + name)
        text = data.decode("utf-8", errors="replace")
        for reason, pattern in patterns.items():
            if re.search(pattern, text):
                issues.append((name, reason))
        if name == "config.example.json":
            import json, urllib.parse
            config = json.loads(text)
            for item in [config["qbittorrent"], *config["sonarr"].values()]:
                host = urllib.parse.urlsplit(item["url"]).hostname or ""
                if not host.endswith(".example.invalid"):
                    issues.append((name, "non-placeholder endpoint"))
                for key in ("api_key", "username", "password"):
                    if key in item and item[key] != "REPLACE_ME":
                        issues.append((name, "non-placeholder credential"))
    for name, reason in issues:
        print(f"BLOCKED: {name}: {reason}")
    if not issues:
        print("Content checks passed; manual identity/deployment review still required.")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
