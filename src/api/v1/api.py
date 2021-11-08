from flask import Blueprint
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from config import flask_config

routes = Blueprint('v1', __name__, url_prefix='/api/v1')

limiter = Limiter(
    key_func=get_remote_address,
    default_limits=['200 per day', '50 per hour'],
    enabled=not flask_config.DEBUG,
    storage_uri=flask_config.REDIS_URI,
)

from . import routes_2fa  # noqa
from . import routes_oauth  # noqa
from . import routes_role  # noqa
from . import routes_token  # noqa
from . import routes_user  # noqa
