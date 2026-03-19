from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class VersionMetadata:
    git_version: str | None
    commit_sha: str | None
    branch: str | None
    source: str
    build_number: str | None
    workflow_run_id: str | None
    workflow_name: str | None


@dataclass(frozen=True)
class VersionMetadataDocument:
    values: dict[str, str]
