from __future__ import annotations

from collections.abc import Iterable

from domain.health.models import VersionMetadata
from domain.health.providers import VersionMetadataProvider


class VersionMetadataResolver:
    def __init__(self, providers: Iterable[VersionMetadataProvider]) -> None:
        self._providers = tuple(providers)

    def resolve(self) -> VersionMetadata:
        for provider in self._providers:
            metadata = provider.provide()
            if metadata is not None:
                return metadata

        return VersionMetadata(
            git_version=None,
            commit_sha=None,
            branch=None,
            source="unavailable",
            build_number=None,
            workflow_run_id=None,
            workflow_name=None,
        )
