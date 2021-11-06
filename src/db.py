import logging

import redis
from flask import Flask
from flask_sqlalchemy import SQLAlchemy

from config import DB_HOST, DB_NAME, DB_PASSWORD, DB_USER, REDIS_HOST, REDIS_PORT

logger = logging.getLogger(__name__)

db = SQLAlchemy()
redis_db = redis.Redis(host=REDIS_HOST, port=REDIS_PORT, db=0)


def init_db(app: Flask):
    logger.debug(f'init db {DB_NAME}')

    app.config['SQLALCHEMY_DATABASE_URI'] = f'postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}/{DB_NAME}'
    db.init_app(app)
