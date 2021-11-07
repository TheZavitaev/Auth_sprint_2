import os
from distutils.util import strtobool

from dotenv import load_dotenv
from pydantic import BaseSettings

load_dotenv()

# Postgres
DB_HOST = os.getenv('POSTGRES_HOST', '127.0.0.1')
DB_USER = os.getenv('POSTGRES_USER', 'postgres')
DB_PASSWORD = os.getenv('POSTGRES_PASSWORD', 'postgres')
DB_NAME = os.getenv('POSTGRES_DB', 'auth_service')

# Redis
REDIS_HOST = os.getenv('REDIS_HOST', 6379)
REDIS_PORT = os.getenv('REDIS_PORT', 6379)

# App running mode
DEBUG = bool(strtobool(os.getenv('DEBUG', 'False')))

# logger settings
LOG_LEVEL = 'DEBUG' if DEBUG else 'INFO'


# JWT settings
class TokenConfig(BaseSettings):
    JWT_ACCESS_TOKEN_EXPIRES: int = os.getenv('JWT_ACCESS_TOKEN_EXPIRES')
    JWT_REFRESH_TOKEN_EXPIRES: int = os.getenv('JWT_REFRESH_TOKEN_EXPIRES')
    JWT_ALGORITHM: str = 'RS256'

    JSONIFY_PRETTYPRINT_REGULAR: bool = True


# Flask settings
class Settings(BaseSettings):
    LOG_LEVEL: str = LOG_LEVEL

    # Redis
    REDIS_HOST = REDIS_HOST
    REDIS_PORT = REDIS_PORT

    REDIS_SOCKET: str = f'{REDIS_HOST:{REDIS_PORT}}'

    SQLALCHEMY_DATABASE_URI: str = f'postgresql://{DB_USER}@{DB_HOST}:5432/auth'
    SQLALCHEMY_TRACK_MODIFICATIONS: bool = False

    DEBUG: bool = DEBUG

    SECRET_KEY: str = os.getenv('SECRET_KEY')
    JWT_PRIVATE_KEY: str = os.getenv('JWT_PRIVATE_KEY')
    JWT_PUBLIC_KEY: str = os.getenv('JWT_PUBLIC_KEY')

    GOOGLE_CLIENT_ID: str = os.getenv('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET: str = os.getenv('GOOGLE_CLIENT_SECRET')


flask_config = Settings()
jwt_config = TokenConfig()
