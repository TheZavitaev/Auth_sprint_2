from flask import Blueprint

routes = Blueprint('v1', __name__, url_prefix='/api/v1')

from . import routes_role  # noqa
from . import routes_user  # noqa
from . import routes_token  # noqa
from . import routes_oauth  # noqa
from . import routes_2fa  # noqa
