from apispec import APISpec
from apispec_webframeworks.flask import FlaskPlugin
from flask import current_app

from api.v1.api_models import (
    RoleIn,
    RoleOut,
    TokenGrantOut,
    TokenInPassword,
    TokenRevokeIn,
    UserIn,
    UserInfoOut,
    UserLoginRecord,
    UserLoginRecordsOut,
    UserPatchIn,
)


def get_api_spec():
    spec = APISpec(
        title='Auth API',
        version='0.1.0',
        openapi_version='3.0.2',
        info=dict(description='Service for token-based authentication'),
        plugins=[FlaskPlugin()],
    )

    jwt_access = {
        'type': 'http',
        'scheme': 'bearer',
        'bearerFormat': 'JWT'
    }
    jwt_refresh = {
        'type': 'http',
        'scheme': 'bearer',
        'bearerFormat': 'JWT'
    }

    spec.components.security_scheme('jwt_access', jwt_access)
    spec.components.security_scheme('jwt_refresh', jwt_refresh)

    with current_app.test_request_context():
        for rule in current_app.url_map.iter_rules():
            spec.path(view=current_app.view_functions[rule.endpoint])

    spec.components.schema('UserIn', UserIn.schema())
    spec.components.schema('UserPatchIn', UserPatchIn.schema())
    spec.components.schema('UserInfoOut', UserInfoOut.schema())
    spec.components.schema('UserLoginRecord', UserLoginRecord.schema())
    spec.components.schema('UserLoginRecordsOut', UserLoginRecordsOut.schema())
    spec.components.schema('TokenInPassword', TokenInPassword.schema())
    spec.components.schema('TokenRevokeIn', TokenRevokeIn.schema())
    spec.components.schema('TokenGrantOut', TokenGrantOut.schema())
    spec.components.schema("RoleIn", RoleIn.schema())
    spec.components.schema("RoleOut", RoleOut.schema())

    return spec
