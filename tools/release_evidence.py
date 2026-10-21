"""Record and verify the exact candidate digest published by one Actions run.

Metadata is operational evidence, never code to execute. No registry writes here.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import zipfile


class EvidenceError(ValueError):
    pass


def require(condition):
    if not condition:
        raise EvidenceError("publication_evidence_invalid")


def digest_valid(value):
    return isinstance(value, str) and re.fullmatch(r"sha256:[a-f0-9]{64}", value) is not None


def integer(value):
    return type(value) is int and value > 0


def validate_run(run, repository, run_id):
    require(isinstance(run, dict) and integer(run_id))
    require(run.get("id") == run_id and type(run.get("id")) is int)
    require(run.get("status") == "completed" and run.get("conclusion") == "success")
    require(run.get("path") == ".github/workflows/container.yml")
    require(run.get("event") in ("workflow_dispatch", "schedule"))
    require(isinstance(run.get("head_repository"), dict)
            and run["head_repository"].get("full_name") == repository)
    require(isinstance(run.get("head_sha"), str)
            and re.fullmatch(r"[a-f0-9]{40}", run["head_sha"]) is not None)
    require(integer(run.get("run_attempt")))


def validate_record(record, run, repository, run_id, digest):
    validate_run(run, repository, run_id)
    require(digest_valid(digest) and isinstance(record, dict))
    require(set(record) == {"schema", "repository", "run_id", "run_attempt", "revision", "digest", "image", "tag"})
    require(type(record["schema"]) is int and record["schema"] == 1)
    require(integer(record["run_id"]) and record["run_id"] == run_id)
    require(integer(record["run_attempt"]) and record["run_attempt"] == run["run_attempt"])
    require(record["repository"] == repository and record["revision"] == run["head_sha"])
    require(record["digest"] == digest)
    require(record["image"] == "ghcr.io/" + repository.lower())
    tag = f"sha-{run['head_sha']}-run-{run_id}-{run['run_attempt']}"
    require(record["tag"] == tag)
    return record


def select_artifact(pages, run, repository, run_id):
    validate_run(run, repository, run_id)
    require(isinstance(pages, list))
    name = f"publication-{run_id}-{run['run_attempt']}"
    matches = []
    for page in pages:
        require(isinstance(page, dict) and isinstance(page.get("artifacts"), list))
        matches.extend(item for item in page["artifacts"]
                       if isinstance(item, dict) and item.get("name") == name)
    require(len(matches) == 1)
    artifact = matches[0]
    require(artifact.get("expired") is False and integer(artifact.get("id")))
    require(digest_valid(artifact.get("digest")))
    provenance = artifact.get("workflow_run")
    require(isinstance(provenance, dict) and type(provenance.get("id")) is int
            and provenance["id"] == run_id and provenance.get("head_sha") == run["head_sha"])
    return {"id": artifact["id"], "digest": artifact["digest"]}


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result)
        result[key] = value
    return result


def read_json(path):
    return json.loads(Path(path).read_text(), object_pairs_hook=no_duplicate_keys)


def verify_archive(path, archive_digest, run, repository, run_id, digest):
    require(digest_valid(archive_digest))
    path = Path(path)
    require(path.stat().st_size <= 1024 * 1024)
    require("sha256:" + hashlib.sha256(path.read_bytes()).hexdigest() == archive_digest)
    with zipfile.ZipFile(path) as archive:
        require(archive.namelist() == ["publication.json"])
        require(archive.getinfo("publication.json").file_size <= 16384)
        record = json.loads(archive.read("publication.json"), object_pairs_hook=no_duplicate_keys)
    return validate_record(record, run, repository, run_id, digest)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    record = sub.add_parser("record")
    record.add_argument("--digest", required=True)
    record.add_argument("--output", type=Path, required=True)
    for operation in ("select", "verify"):
        command = sub.add_parser(operation)
        command.add_argument("--run", type=Path, required=True)
        command.add_argument("--repository", required=True)
        command.add_argument("--run-id", type=int, required=True)
        if operation == "select":
            command.add_argument("--artifacts", type=Path, required=True)
        else:
            command.add_argument("--archive", type=Path, required=True)
            command.add_argument("--archive-digest", required=True)
            command.add_argument("--digest", required=True)
    args = parser.parse_args()
    try:
        if args.operation == "record":
            require(digest_valid(args.digest))
            repository = os.environ["GITHUB_REPOSITORY"]
            revision = os.environ["GITHUB_SHA"]
            run_id, attempt = int(os.environ["GITHUB_RUN_ID"]), int(os.environ["GITHUB_RUN_ATTEMPT"])
            value = {"schema": 1, "repository": repository, "revision": revision,
                     "run_id": run_id, "run_attempt": attempt, "digest": args.digest,
                     "image": "ghcr.io/" + repository.lower(),
                     "tag": f"sha-{revision}-run-{run_id}-{attempt}"}
            with args.output.open("x") as output:
                json.dump(value, output, sort_keys=True)
            print("Publication digest recorded")
        else:
            run = read_json(args.run)
            if args.operation == "select":
                print(json.dumps(select_artifact(read_json(args.artifacts), run, args.repository, args.run_id)))
            else:
                verify_archive(args.archive, args.archive_digest, run, args.repository, args.run_id, args.digest)
                print("Exact published run/digest evidence verified")
        return 0
    except Exception:
        # API, JSON and archive content are untrusted diagnostic data.
        print("Publication evidence unavailable or invalid")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
