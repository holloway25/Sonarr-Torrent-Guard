"""Allow only compatible dependency refreshes of already released image inputs."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess


BASE = "python:3.15-slim-trixie"
IMAGE_FILES = ("guard.py", "production.py", "safety.py", "maintenance.py", "public.py",
               "authorization.py", "routine.py", "workflow.py", "reports.py", "retention.py",
               "container_worker.py", "LICENSE")
FROM = re.compile(r"\AFROM python:3\.15-slim-trixie@sha256:[a-f0-9]{64}\n")
OLD_APT = "RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata ca-certificates \\\n"
NEW_APT = ("RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get upgrade -y --no-install-recommends \\\n"
           "    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends tzdata ca-certificates \\\n")


class DependencyReviewRequired(ValueError):
    pass


def normalized_recipe(data, baseline=False):
    text = data.decode("utf-8")
    if FROM.match(text) is None:
        raise DependencyReviewRequired("base_family_change_requires_review")
    copied = [name for line in text.splitlines() if line.startswith("COPY ")
              for name in line.split()[1:-1]]
    if len(copied) != len(IMAGE_FILES) or set(copied) != set(IMAGE_FILES):
        raise DependencyReviewRequired("image_copy_manifest_requires_review")
    # One narrowly authorized bootstrap: add package upgrades to the old release.
    # Never normalize away a removed upgrade step in a new candidate.
    if baseline and OLD_APT in text and NEW_APT not in text:
        text = text.replace(OLD_APT, NEW_APT, 1)
    if NEW_APT not in text:
        raise DependencyReviewRequired("package_upgrade_step_required")
    return FROM.sub("FROM " + BASE + "@APPROVED_FAMILY_DIGEST\n", text, count=1)


def code_fingerprint(files):
    if set(files) != set(IMAGE_FILES):
        raise DependencyReviewRequired("image_source_set_changed")
    values = {name: hashlib.sha256(files[name]).hexdigest() for name in IMAGE_FILES}
    return hashlib.sha256(json.dumps(values, sort_keys=True).encode()).hexdigest()


def compare(candidate, baseline):
    if code_fingerprint({k: v for k, v in candidate.items() if k != "Dockerfile"}) != code_fingerprint(
            {k: v for k, v in baseline.items() if k != "Dockerfile"}):
        raise DependencyReviewRequired("application_or_license_change_requires_review")
    if normalized_recipe(candidate["Dockerfile"]) != normalized_recipe(baseline["Dockerfile"], baseline=True):
        raise DependencyReviewRequired("build_recipe_change_requires_review")


def git_inputs(revision):
    if re.fullmatch(r"[a-f0-9]{40}", revision) is None:
        raise ValueError("invalid_revision")
    return {name: subprocess.run(["git", "show", revision + ":" + name], check=True,
                                 capture_output=True).stdout for name in (*IMAGE_FILES, "Dockerfile")}


def image_script():
    # Pure file hashing: do not import/execute guard code or open runtime config.
    return ("import hashlib,json; from pathlib import Path; "
            "files=" + repr(IMAGE_FILES) + "; "
            "values={n:hashlib.sha256((Path('/app')/n).read_bytes()).hexdigest() for n in files}; "
            "print(hashlib.sha256(json.dumps(values,sort_keys=True).encode()).hexdigest())")


def newer_build(candidate_run, candidate_attempt, baseline_run, baseline_attempt):
    if any(not isinstance(v, str) or re.fullmatch(r"[1-9][0-9]*", v) is None
           for v in (candidate_run, candidate_attempt)):
        raise DependencyReviewRequired("build_order_unavailable")
    if baseline_run == "":
        # Original pre-maintenance release has no build-order labels.
        if baseline_attempt != "":
            raise DependencyReviewRequired("build_order_unavailable")
        return
    values = (candidate_run, candidate_attempt, baseline_run, baseline_attempt)
    if any(not isinstance(v, str) or re.fullmatch(r"[1-9][0-9]*", v) is None for v in values):
        raise DependencyReviewRequired("build_order_unavailable")
    if (int(candidate_run), int(candidate_attempt)) <= (int(baseline_run), int(baseline_attempt)):
        raise DependencyReviewRequired("older_or_repeated_build")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    check = sub.add_parser("compare")
    check.add_argument("--candidate", required=True)
    check.add_argument("--baseline", required=True)
    render = sub.add_parser("render")
    render.add_argument("--digest", required=True)
    render.add_argument("--output", type=Path, required=True)
    render.add_argument("--source", type=Path, default=Path("Dockerfile"))
    sub.add_parser("image-script")
    order = sub.add_parser("newer")
    for name in ("candidate-run", "candidate-attempt", "baseline-run", "baseline-attempt"):
        order.add_argument("--" + name, required=True)
    args = parser.parse_args()
    try:
        if args.operation == "compare":
            compare(git_inputs(args.candidate), git_inputs(args.baseline))
            print("Released application and build recipe unchanged")
        elif args.operation == "render":
            if re.fullmatch(r"sha256:[a-f0-9]{64}", args.digest) is None:
                raise ValueError("invalid_digest")
            data = args.source.read_bytes()
            normalized_recipe(data)
            with args.output.open("x") as output:
                output.write(FROM.sub("FROM " + BASE + "@" + args.digest + "\n", data.decode(), count=1))
        elif args.operation == "image-script":
            print(image_script())
        else:
            newer_build(args.candidate_run, args.candidate_attempt, args.baseline_run, args.baseline_attempt)
        return 0
    except DependencyReviewRequired as error:
        print(str(error))
        return 2
    except Exception:
        print("dependency_release_evidence_unavailable")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
