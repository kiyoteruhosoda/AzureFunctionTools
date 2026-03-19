from __future__ import annotations

import json
import logging
from dataclasses import asdict
from datetime import datetime, timezone

import azure.functions as func

from application.health.versioning import VersionMetadataResolver
from infrastructure.health.providers import (
    DocumentVersionMetadataProvider,
    FileVersionMetadataDocumentProvider,
)

bp = func.Blueprint()


@bp.route(route="healthz", methods=["GET"], auth_level=func.AuthLevel.ANONYMOUS)
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint."""
    logging.info("health_check triggered.")

    version_metadata = VersionMetadataResolver(
        providers=(
            DocumentVersionMetadataProvider(FileVersionMetadataDocumentProvider()),
        )
    ).resolve()

    body = {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "version": asdict(version_metadata),
    }

    return func.HttpResponse(
        json.dumps(body),
        status_code=200,
        mimetype="application/json",
    )
