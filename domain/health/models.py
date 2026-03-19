from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Any


@dataclass(frozen=True)
class VersionMetadata:
    git_version: str | None
    commit_sha: str | None
    branch: str | None
    source: str
    build_number: str | None
    workflow_run_id: str | None
    workflow_name: str | None

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
