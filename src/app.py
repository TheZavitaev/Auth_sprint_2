import logging

import click
from flask import Flask, jsonify
from flask.cli import with_appcontext
from flask_jwt_extended import JWTManager
from flask_swagger_ui import get_swaggerui_blueprint

import auth
import config
import token_store
from api.v1 import api
from db import db, init_db
from db_models import User


def create_app():
    app = Flask(__name__)

    app.config.from_object(config.flask_config)

    logging.basicConfig(
        level=app.config['LOG_LEVEL'],
    )

    jwt = JWTManager()
    jwt.init_app(app)
    create_jwt(app, jwt)

    init_storage(app)
    prepare_db(app)

    create_command(app)
    create_swagger(app)

    app.register_blueprint(api.routes)

    return app


def init_storage(flask_app: Flask) -> None:
    token_store.init(
        flask_app.config['REDIS_HOST'],
        flask_app.config['REDIS_PORT'],
        flask_app.config['JWT_REFRESH_TOKEN_EXPIRES']
    )
    return None


def prepare_db(flask_app: Flask) -> None:
    @flask_app.before_first_request
    def startup():
        init_db(flask_app)
        flask_app.app_context().push()
        db.create_all()

    @flask_app.teardown_appcontext
    def after_request(response):
        db.session.remove()
        return response

    return None


def create_swagger(flask_app: Flask) -> None:
    @flask_app.route('/static/swagger.json')
    def get_swagger():
        from openapi_spec import get_api_spec

        return jsonify(get_api_spec().to_dict())

    SWAGGER_URL = '/swagger'
    API_URL = '/static/swagger.json'
    SWAGGERUI_BLUEPRINT = get_swaggerui_blueprint(
        SWAGGER_URL,
        API_URL,
        config={'app_name': 'Auth API'}
    )

    flask_app.register_blueprint(SWAGGERUI_BLUEPRINT, url_prefix=SWAGGER_URL)

    return None


def create_jwt(flask_app: Flask, jwt: JWTManager) -> None:
    flask_app.config.from_object(config.jwt_config)

    @jwt.user_identity_loader
    def user_identity_callback(user):
        return user.id

    @jwt.user_lookup_loader
    def user_lookup_callback(_jwt_header, jwt_data):
        identity = jwt_data['sub']
        return db.session.query(User).filter_by(id=identity).one_or_none()

    @jwt.token_in_blocklist_loader
    def token_in_blocklist_callback(_jwt_header, jwt_payload):
        if jwt_payload.get('type') == 'access':
            return False
        jti = jwt_payload.get('jti')
        return not token_store.does_refresh_token_exist(jti)

    @jwt.additional_claims_loader
    def add_claims_to_access_token(user: User):
        return {'permissions': [permission for permission in user.permissions]}

    return None


def create_command(flask_app: Flask) -> None:
    @flask_app.cli.command('initial_db')
    @with_appcontext
    def initial_db():
        init_db(flask_app)
        flask_app.app_context().push()
        db.create_all()

    @flask_app.cli.command('create_user')
    @click.argument('name')
    @click.argument('password')
    @with_appcontext
    def create_user(name, password):
        auth.create_user(name, password)

    @flask_app.cli.command('cleanup')
    @with_appcontext
    def cleanup():
        db.drop_all(app)

    return None


app = create_app()