"""Repository content checks. Never print matched sensitive values."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import urllib.parse
import xml.etree.ElementTree as ET


GUARD_SETTING = r"STGUARD_(?:QBIT|SONARR_[A-Z0-9_]+)_(URL|API_KEY|USERNAME|PASSWORD)"


def is_example_endpoint(url):
    try:
        endpoint = urllib.parse.urlsplit(url)
        return ((endpoint.hostname or "").endswith(".example.invalid")
                and endpoint.username is None and endpoint.password is None)
    except ValueError:
        return False


def template_issues(text):
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return ["invalid XML template"]
    issues = []
    for item in root.iter("Config"):
        setting = re.fullmatch(GUARD_SETTING, item.get("Target", ""))
        if setting is None:
            continue
        default = item.get("Default", "")
        value = "".join(item.itertext()).strip()
        if setting[1] == "URL":
            if not is_example_endpoint(default) or (value and not is_example_endpoint(value)):
                issues.append("non-placeholder endpoint")
        elif default != "REPLACE_ME" or value not in ("", "REPLACE_ME"):
            issues.append("non-placeholder credential")
    return issues


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
        if (leaf.startswith("handoff") or leaf.endswith(".env") or leaf.startswith(".env.")
                or (leaf.startswith("connections") and leaf.endswith(".json"))
                or leaf.startswith((".guard-", ".batch-")) or leaf == ".connections-validation.json"
                or leaf in ("config.json", "batch-state.json", "routine-authorization.json",
                            "container-live-scope.json", "container-live-journal.json", "container-status.json",
                            "container-journal-binding.json")
                or leaf.endswith((".log", ".lock", ".zip", ".sqlite3")) or ".sqlite3-" in leaf or ".log." in leaf
                or any(x in ("local", "downloads", "staging") for x in parts)):
            issues.append((name, "prohibited runtime or handoff artifact"))
        data = Path(name).read_bytes() if args.all else git("show", ":" + name)
        text = data.decode("utf-8", errors="replace")
        for reason, pattern in patterns.items():
            if re.search(pattern, text):
                issues.append((name, reason))
        if name == "config.example.json":
            config = json.loads(text)
            examples = [config["qbittorrent"], *config["sonarr"].values()]
            examples.extend({"url": item["download_client_binding"]["endpoint"]}
                            for item in config["sonarr"].values())
            for item in examples:
                if not is_example_endpoint(item["url"]):
                    issues.append((name, "non-placeholder endpoint"))
                for key in ("api_key", "username", "password"):
                    if key in item and item[key] != "REPLACE_ME":
                        issues.append((name, "non-placeholder credential"))
        if leaf.endswith(".xml"):
            issues.extend((name, reason) for reason in template_issues(text))
        for field, value in re.findall(rf"(?m)^[ \t]*(?:export[ \t]+)?{GUARD_SETTING}[ \t]*=(.*)$", text):
            if field == "URL":
                if not is_example_endpoint(value.strip()):
                    issues.append((name, "non-placeholder endpoint"))
            elif value.strip() != "REPLACE_ME":
                issues.append((name, "non-placeholder credential"))
    for name, reason in issues:
        print(f"BLOCKED: {name}: {reason}")
    if not issues:
        print("Content checks passed; manual identity/deployment review still required.")
    return bool(issues)


if __name__ == "__main__":
    sys.exit(main())
