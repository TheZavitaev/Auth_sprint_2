import http
import logging

from flask import Blueprint, jsonify, make_response, request, url_for
from flask_jwt_extended import current_user, get_jwt, jwt_required
from werkzeug.exceptions import BadRequest, Forbidden

import auth
from api.v1.api_models import (
    RoleIn,
    TokenGrantOut,
    TokenInPassword,
    UserIn,
    UserInfoOut,
    UserLoginRecordsOut,
    UserPatchIn,
)
from api.v1.utils import get_oauth, parse_obj_raise
from db import db
from db_models import LoginRecord, ThirdPartyAccount, User

routes = Blueprint('v1', __name__, url_prefix='/api/v1')

logger = logging.getLogger(__name__)


@routes.route('/user', methods=['POST'])
def create_user():
    """create_user
        ---
        post:
          description: Create user
          summary: Create user
          requestBody:
            content:
              application/json:
                schema: UserIn
          responses:
            201:
              description: Ok
              headers:
                Location:
                  description: uri with user info
                  schema:
                    type: string
                    format: uri
                    example: /user/dbdbed6b-95d1-4a4f-b7b9-6a6f78b6726e
              content:
                application/json:
                  schema: UserInfoOut
            409:
              description: Conflict
          tags:
            - user
        """

    logger.debug('Registration')

    user_data = parse_obj_raise(UserIn, request.get_json())

    logger.info(f'User with email: {user_data.email}')

    user = auth.create_user(user_data.email, user_data.password.get_secret_value())
    resp = make_response('Created', http.HTTPStatus.CREATED)
    resp.headers['Location'] = f'{url_for(".create_user")}/{user.id}'

    return resp


@routes.route('/user/<string:user_id>', methods=['GET'])
@jwt_required()
def get_user_info(user_id):
    """get_user_info
    ---
    get:
      description: Get user info
      summary: Get detailed user info
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string
      responses:
        200:
          description: Ok
          content:
            application/json:
              schema: UserInfoOut
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - user
    """

    logger.debug('get user info')

    if str(current_user.id) != user_id:
        raise Forbidden

    return jsonify(
        UserInfoOut(
            id=str(current_user.id),
            email=current_user.email,
            registered_at=current_user.registered_at,
            active=current_user.active,
            roles=[role.name for role in current_user.roles],
        ).dict()
    )


@routes.route('/user/<string:user_id>', methods=['PATCH'])
@jwt_required()
def change_user_info(user_id):
    """change_user_info
    ---
    patch:
      description: Change user info
      summary: Change user email or password
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string
      requestBody:
        content:
          'application/json':
            schema: UserPatchIn
      responses:
        200:
          description: Ok
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - user
    """

    logger.debug('change user info')

    if str(current_user.id) != user_id:
        raise Forbidden

    patch_data = parse_obj_raise(UserPatchIn, request.get_json())

    if patch_data.email:
        current_user.email = patch_data.email

    if patch_data.new_password_1:
        current_user.hashed_password = auth.hash_password(
            patch_data.new_password_1.get_secret_value()
        )

    db.session.add(current_user)
    db.session.commit()

    return 'OK', http.HTTPStatus.OK


@routes.route('/user/<string:user_id>/login_history', methods=['GET'])
@jwt_required()
def get_login_history(user_id):
    """get_login_history
    ---
    get:
      description: Get login history
      summary: Get login history
      security:
        - jwt_access: []
      parameters:
      - name: user_id
        in: path
        description: user_id
        schema:
          type: string
      responses:
        200:
          description: Return login history
          content:
            application/json:
              schema: UserLoginRecordsOut
        401:
          description: Unauthorized
        403:
          description: Forbidden
      tags:
        - login_history
    """

    logger.debug('get user login history')

    if str(current_user.id) != user_id:
        raise Forbidden

    records = db.session.query(LoginRecord).all()
    login_records = [record.to_api_model() for record in records]

    return jsonify(
        UserLoginRecordsOut(logins=login_records).dict()
    )


@routes.route('/create_token', methods=['POST'])
def create_token_pair():
    """create_token_pair
    ---
    post:
      description: Create token pair
      summary: Create new token pair for device
      requestBody:
        content:
          'application/json':
            schema: TokenInPassword
      responses:
        200:
          description: Return new tokens
          content:
            application/json:
              schema: TokenGrantOut
        400:
          description: Access error
      tags:
        - token
    """

    logger.debug('Create token pair')
    token_data = parse_obj_raise(TokenInPassword, request.get_json())

    user = auth.authenticate_with_email(token_data.email, token_data.password.get_secret_value())
    access_token, refresh_token = auth.issue_tokens(user, request.user_agent, request.remote_addr)

    return jsonify(
        TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
    )


@routes.route('/delete_token', methods=['DELETE'])
@jwt_required()
def revoke_refresh_token():
    """revoke_refresh_token
    ---
    delete:
      description: Revoke refresh Token
      summary: Revoke current refresh_token or all user's refresh_tokens
      security:
        - jwt_access: []
      parameters:
      - name: all
        in: query
        description: whether to logout from all devices
        schema:
          type: boolean
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - token
    """

    logger.debug('logout')

    if request.args.get('all') == 'true':
        auth.logout_all_user_devices(current_user)

    else:
        auth.remove_device_token(current_user, request.user_agent)
    return 'OK', http.HTTPStatus.OK


@routes.route('/refresh_token', methods=['POST'])
@jwt_required(refresh=True)
def update_token_pair():
    """update_token_pair
    ---
    post:
      description: Update token pair
      summary: Revoke current token and create new token pair for device
      security:
        - jwt_refresh: []
      responses:
        200:
          description: OK
          content:
           application/json:
             schema: TokenGrantOut
        401:
          description: Unauthorized
      tags:
        - token
    """

    logger.debug('update token pair')

    token_data = get_jwt()
    access_token, refresh_token = auth.refresh_tokens(current_user, token_data)

    return jsonify(
        TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
    )


@routes.route('/role', methods=['POST'])
@jwt_required()
@auth.require_permissions('role:write')
def create_role():
    """create_role
    ---
    post:
      description: Create new role
      summary: Create new role
      security:
        - jwt_access: []
      requestBody:
        content:
          'application/json':
            schema: RoleIn
      responses:
        200:
          description: OK
          content:
            application/json:
              schema: RoleOut
        401:
          description: Unauthorized
      tags:
        - role
    """

    logger.debug('Create new role')

    role = RoleIn.parse_obj(request.json)
    created_role = auth.create_role(role)

    return created_role


@routes.route('/role/<role_id>', methods=['DELETE'])
@jwt_required()
@auth.require_permissions('role:write')
def remove_role(role_id: int):
    """remove_role
    ---
    delete:
      description: Remove role
      summary: Remove role
      security:
        - jwt_access: []
      parameters:
        - name: role_id
          in: path
          description: role_id
          schema:
            type: integer
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.delete_role(role_id)

    return 'OK', http.HTTPStatus.OK


@routes.route('/role/<role_name>/user/<user_id>', methods=['PUT'])
@jwt_required()
@auth.require_permissions('role:write')
def add_role_to_user(role_name: str, user_id: str):
    """add_role_to_user
    ---
    put:
      description: Add role to user
      summary: Add role to user
      security:
        - jwt_access: []
      parameters:
        - name: user_id
          in: path
          description: user_id
          schema:
            type: string
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.add_role_to_user(role_name, user_id)

    return 'OK', http.HTTPStatus.OK


@routes.route('/role/<role_name>/user/<user_id>', methods=['DELETE'])
@jwt_required()
@auth.require_permissions('role:write')
def remove_role_from_user(role_name: str, user_id: str):
    """remove_role_from_user
    ---
    delete:
      description: Remove role from user
      summary: Remove role from user
      security:
        - jwt_access: []
      parameters:
        - name: user_id
          in: path
          description: user_id
          schema:
            type: string
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.remove_role_from_user(role_name, user_id)
    return 'OK', http.HTTPStatus.OK


@routes.route('/role/<role_name>/permission/<permission_name>', methods=['PUT'])
@jwt_required()
@auth.require_permissions('role:write')
def add_permission_to_role(role_name: str, permission_name: str):
    """Add permission to role
    ---
    put:
      description: Add permission to role
      summary: Add permission to role
      security:
        - jwt_access: []
      parameters:
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string
        - name: permission_name
          in: path
          description: permission_name
          schema:
            type: string
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.add_permission_to_role(role_name, permission_name)
    return 'OK', http.HTTPStatus.OK


@routes.route('/role/<role_name>/permissions/<permission_name>', methods=['DELETE'])
@jwt_required()
@auth.require_permissions('role:write')
def remove_permission_from_role(role_name: str, permission_name: str):
    """remove_permission_from_role
    ---
    delete:
      description: Remove permission from role
      summary: Remove permission from role
      security:
        - jwt_access: []
      parameters:
        - name: role_name
          in: path
          description: role_name
          schema:
            type: string
        - name: permission_name
          in: path
          description: permission_name
          schema:
            type: string
      responses:
        200:
          description: OK
        401:
          description: Unauthorized
      tags:
        - role
    """

    auth.remove_permission_from_role(role_name, permission_name)
    return 'OK', http.HTTPStatus.OK


@routes.route('/oauth_login', methods=['GET'])
def oauth_login():
    """Logging in with OpenID provider
    ---
    get:
      description: Logging in with OpenID provider
      summary: Logging in with openid provider
      parameters:
        - name: provider
          in: query
          description: OIDC provider name
          schema:
            type: string
            enum: [google]
      responses:
        200:
          description: OK
      tags:
        - openid
    """

    provider_name = request.args['provider']

    if not provider_name:
        raise BadRequest('No provider is filled')

    oauth = get_oauth()

    try:
        oauth_provider = getattr(oauth, provider_name)

    except AttributeError:
        raise BadRequest(description='Unknown OpenID Connect (OIDC) provider name')

    redirect_uri = url_for('.oauth_redirect', provider=provider_name, _external=True)

    return oauth_provider.authorize_redirect(redirect_uri=redirect_uri)


@routes.route('/oauth_redirect', methods=['GET'])
def oauth_redirect():
    """Redirect URL for openid
    ---
    get:
      description: Redirect URL for openid
      summary: Redirect URL for openid. If user exists - returns token pair, if user is new — creates user.
      parameters:
        - name: provider
          in: query
          description: OIDC provider name
          schema:
            type: string
            enum: [google]
      responses:
        200:
          description: Return new tokens
          content:
            application/json:
              schema: TokenGrantOut
        201:
          description: Ok
          headers:
            Location:
              description: uri with user info
              schema:
                type: string
                format: uri
                example: /user/dbdbed6b-95d1-4a4f-b7b9-6a6f78b6726e
          content:
            application/json:
              schema: UserInfoOut
        409:
          description: Conflict
      tags:
        - openid
    """

    provider_name = request.args['provider']
    oauth = get_oauth()

    try:
        oauth_provider = getattr(oauth, provider_name)

    except AttributeError:
        raise BadRequest(description='Unknown OpenID Connect (OIDC) provider name')

    token = oauth_provider.authorize_access_token()
    user_info = oauth_provider.parse_id_token(token)

    third_party_id = user_info['sub']

    user = User.get_user_universal(third_party_id=third_party_id)

    if user:
        access_token, refresh_token = auth.issue_tokens(user, request.user_agent, request.remote_addr)

        return jsonify(
            TokenGrantOut(access_token=access_token, refresh_token=refresh_token).dict()
        )

    else:
        user = auth.create_user_from_third_party(third_party_account_id=third_party_id, user_info=user_info)

        resp = make_response('Created', http.HTTPStatus.CREATED)
        resp.headers['Location'] = f'{url_for(".get_user_info", user_id=user.id)}'

        return resp
