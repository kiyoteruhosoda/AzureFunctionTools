from __future__ import annotations

from abc import ABC, abstractmethod

from domain.health.models import VersionMetadata


class VersionMetadataProvider(ABC):
    @abstractmethod
    def provide(self) -> VersionMetadata | None:
        """Return version metadata if the provider can resolve it."""
