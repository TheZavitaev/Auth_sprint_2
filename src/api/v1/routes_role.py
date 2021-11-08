import http
import logging

from flask import request
from flask_jwt_extended import jwt_required

import auth
from api.v1.api import routes
from api.v1.api_models import RoleIn

logger = logging.getLogger(__name__)


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
