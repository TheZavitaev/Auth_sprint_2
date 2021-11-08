import http
import logging

from flask import jsonify, make_response, request, url_for
from flask_jwt_extended import current_user, jwt_required
from werkzeug.exceptions import Forbidden

import auth
from api.v1.api import limiter, routes
from api.v1.api_models import UserIn, UserInfoOut, UserLoginRecordsOut, UserPatchIn
from api.v1.utils import parse_obj_raise
from db import db
from db_models import LoginRecord

logger = logging.getLogger(__name__)


@routes.route('/user', methods=['POST'])
@limiter.limit('1 per day')
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
