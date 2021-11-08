import http
import logging

from flask import jsonify, request
from flask_jwt_extended import current_user, get_jwt, jwt_required

import auth
from api.v1.api import routes
from api.v1.api_models import TokenGrantOut, TokenInPassword
from api.v1.utils import parse_obj_raise

logger = logging.getLogger(__name__)


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
