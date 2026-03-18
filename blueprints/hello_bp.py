import logging

import azure.functions as func

bp = func.Blueprint()


@bp.route(route="hello", methods=["GET", "POST"])
def hello(req: func.HttpRequest) -> func.HttpResponse:
    """Return a greeting message.

    Query param or JSON body:
        name (str): Optional. Name to greet. Defaults to 'World'.

    Returns:
        HttpResponse: 200 with greeting text.
    """
    logging.info("hello function triggered.")

    name = req.params.get("name")
    if not name:
        try:
            body = req.get_json()
        except ValueError:
            body = {}
        name = body.get("name")

    message = f"Hello, {name}!" if name else "Hello, World!"

    return func.HttpResponse(
        message,
        status_code=200,
        mimetype="text/plain",
    )
