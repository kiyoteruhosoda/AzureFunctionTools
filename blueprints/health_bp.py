import json
import logging
from datetime import datetime, timezone

import azure.functions as func

bp = func.Blueprint()


@bp.route(route="healthz", methods=["GET"])
def health_check(req: func.HttpRequest) -> func.HttpResponse:
    """Health check endpoint.

    Returns:
        HttpResponse: 200 with JSON body indicating service status.
    """
    logging.info("health_check triggered.")

    body = {
        "status": "ok",
        "timestamp": datetime.now(timezone.utc).isoformat(),
    }

    return func.HttpResponse(
        json.dumps(body),
        status_code=200,
        mimetype="application/json",
    )