from __future__ import annotations

import os
from pathlib import Path

from domain.health.models import VersionMetadata, VersionMetadataDocument
from domain.health.providers import VersionMetadataDocumentProvider, VersionMetadataProvider


class FileVersionMetadataDocumentProvider(VersionMetadataDocumentProvider):
    def __init__(self, file_path: str | Path | None = None) -> None:
        configured_path = file_path or os.getenv("HEALTHZ_VERSION_FILE_PATH") or "version-metadata.txt"
        self._file_path = Path(configured_path)

    def provide(self) -> VersionMetadataDocument | None:
        if not self._file_path.is_file():
            return None

        pairs: dict[str, str] = {}
        for raw_line in self._file_path.read_text(encoding="utf-8").splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue

            key, value = line.split("=", 1)
            pairs[key.strip()] = value.strip()

        if not pairs:
            return None

        return VersionMetadataDocument(values=pairs)


class DocumentVersionMetadataProvider(VersionMetadataProvider):
    def __init__(self, document_provider: VersionMetadataDocumentProvider) -> None:
        self._document_provider = document_provider

    def provide(self) -> VersionMetadata | None:
        document = self._document_provider.provide()
        if document is None:
            return None

        return VersionMetadata(
            git_version=document.values.get("git_version"),
            commit_sha=document.values.get("commit_sha"),
            branch=document.values.get("branch"),
            source=document.values.get("source", "file"),
            build_number=document.values.get("build_number"),
            workflow_run_id=document.values.get("workflow_run_id"),
            workflow_name=document.values.get("workflow_name"),
        )
