import http

from flask import jsonify, make_response, request, url_for

import auth
from api.v1.api import routes
from api.v1.api_models import TokenGrantOut
from api.v1.utils import check_oidc_provider
from db_models import User


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

    oauth_provider, provider_name = check_oidc_provider(request)

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

    oauth_provider, provider_name = check_oidc_provider(request)

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
