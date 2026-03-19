from __future__ import annotations

import os
import subprocess
from pathlib import Path

OUTPUT_PATH = Path(os.getenv("HEALTHZ_VERSION_FILE_PATH", "version-metadata.txt"))


def _git(*args: str) -> str | None:
    try:
        completed = subprocess.run(
            ["git", *args],
            check=True,
            capture_output=True,
            text=True,
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        return None

    return completed.stdout.strip() or None


def _first(*values: str | None) -> str | None:
    return next((value for value in values if value), None)


def build_lines() -> list[str]:
    source = "github_actions" if os.getenv("GITHUB_ACTIONS") == "true" else "build"
    git_version = _git("describe", "--tags", "--always", "--dirty") or _git("rev-parse", "--short", "HEAD")
    commit_sha = _first(os.getenv("GITHUB_SHA"), _git("rev-parse", "HEAD"))
    branch = _first(os.getenv("GITHUB_REF_NAME"), _git("rev-parse", "--abbrev-ref", "HEAD"))
    build_number = _first(os.getenv("GITHUB_RUN_NUMBER"), os.getenv("BUILD_BUILDNUMBER"))
    workflow_run_id = _first(os.getenv("GITHUB_RUN_ID"), os.getenv("BUILD_BUILDID"))
    workflow_name = _first(os.getenv("GITHUB_WORKFLOW"), os.getenv("BUILD_DEFINITIONNAME"))

    values = {
        "git_version": git_version,
        "commit_sha": commit_sha,
        "branch": branch,
        "source": source,
        "build_number": build_number,
        "workflow_run_id": workflow_run_id,
        "workflow_name": workflow_name,
    }

    return [f"{key}={value}" for key, value in values.items() if value is not None]


def main() -> None:
    OUTPUT_PATH.write_text("\n".join(build_lines()) + "\n", encoding="utf-8")
    print(f"generated: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
