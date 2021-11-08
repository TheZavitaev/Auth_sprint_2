import http
from uuid import UUID

import pyotp
from flask import jsonify
from flask_jwt_extended import current_user, jwt_required
from werkzeug.exceptions import Forbidden

from api.v1.api import limiter, routes
from auth import issue_tokens
from db_models import User


@routes.route('/sync/<string:user_id>', methods=['GET'])
@jwt_required()
@limiter.limit('5 per hour')
def generate_secrete_key(user_id: UUID):
    """2 FA generate secrete key
     ---
     get:
       description: generate one-time passwords
       summary: generate one-time passwords
       security:
         - jwt_access: []
       parameters:
       - name: user_id
         in: query
         description: generate one-time passwords
         schema:
           type: str
       responses:
         200:
           description: OK
         401:
           description: Unauthorized
       tags:
         - 2fa
     """

    secret = pyotp.random_base32()
    user = User.get_by_id(user_id)

    if str(current_user.id) != user_id:
        raise Forbidden

    user.totp_secret = secret
    user.save()
    totp = pyotp.TOTP(secret)
    provisioning_url = totp.provisioning_uri(name=user.email, issuer_name='Auth app')

    return jsonify(url=provisioning_url, id=user_id)


@routes.route('/sync/<string:user_id>', methods=['POST'])
@jwt_required()
def sync(data, user_id: UUID):
    """2 FA sync
     ---
     post:
       description: verifying one-time passwords
       summary: verifying one-time passwords
       security:
         - jwt_access: []
       parameters:
       - name: all
         in: query
         description: verifying one-time passwords
         schema:
           type: boolean
       responses:
         200:
           description: OK
         401:
           description: Unauthorized
       tags:
         - 2fa
     """

    user = User.get_by_id(user_id)
    secret = user.totp_secret
    if str(current_user.id) != user_id:
        raise Forbidden
    totp = pyotp.TOTP(secret)

    code = data.pop('code')

    if not totp.verify(code):
        return jsonify(msg='Failed authorization. Wrong code'), http.HTTPStatus.UNAUTHORIZED

    user.is_verified = True
    user.save()

    return issue_tokens(user)
