import azure.functions as func

from blueprints.hello_bp import bp as hello_bp
from blueprints.goodbye_bp import bp as goodbye_bp
from blueprints.get_globalip import bp as get_globalip
from blueprints.health_bp import bp as health_bp

# Register all blueprints
app = func.FunctionApp()
app.register_blueprint(hello_bp)
app.register_blueprint(goodbye_bp)
app.register_blueprint(get_globalip)
app.register_blueprint(health_bp)
    