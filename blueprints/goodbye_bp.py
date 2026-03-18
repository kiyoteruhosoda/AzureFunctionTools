import logging

import azure.functions as func

bp = func.Blueprint()


@bp.route(route="goodbye", methods=["GET", "POST"])
def goodbye(req: func.HttpRequest) -> func.HttpResponse:
    """Return a farewell message.

    Query param or JSON body:
        name (str): Optional. Name to say goodbye to. Defaults to 'World'.

    Returns:
        HttpResponse: 200 with farewell text.
    """
    logging.info("goodbye function triggered.")

    name = req.params.get("name")
    if not name:
        try:
            body = req.get_json()
        except ValueError:
            body = {}
        name = body.get("name")

    message = f"Goodbye, {name}!" if name else "Goodbye, World!"

    return func.HttpResponse(
        message,
        status_code=200,
        mimetype="text/plain",
    )
