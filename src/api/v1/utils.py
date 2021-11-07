from typing import Type, TypeVar

import pydantic
from authlib.integrations.flask_client import OAuth
from flask import current_app
from passlib import pwd
from pydantic import ValidationError
from werkzeug.exceptions import BadRequest

from exceptions import RequestValidationError

BM = TypeVar('BM', bound=pydantic.BaseModel)


def parse_obj_raise(model_type: Type[BM], data: dict) -> BM:
    try:
        user_data = pydantic.parse_obj_as(model_type, data)
        return user_data

    except ValidationError as e:
        raise RequestValidationError(e)


def get_oauth() -> OAuth:
    return current_app.extensions['authlib.integrations.flask_client']


def generate_random_password(length=12) -> str:
    return pwd.genword(length=length)


def check_oidc_provider(request):
    provider_name = request.args['provider']

    if not provider_name:
        raise BadRequest('No provider is filled')

    oauth = get_oauth()

    try:
        oauth_provider = getattr(oauth, provider_name)

    except AttributeError:
        raise BadRequest(description='Unknown OpenID Connect (OIDC) provider name')

    return oauth_provider, provider_name
