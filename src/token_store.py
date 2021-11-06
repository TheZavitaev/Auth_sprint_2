import logging
from typing import Optional

import redis
from werkzeug.user_agent import UserAgent

logger = logging.getLogger(__name__)

client: Optional[redis.StrictRedis] = None

refresh_token_ttl = None


def user_agent_to_device_id(user_agent: UserAgent) -> str:
    return user_agent.string


def replace_refresh_token(jti, user_id, device_id):
    remove_refresh_token(user_id, device_id)
    put_refresh_token(user_id, device_id, jti)


def remove_refresh_token(user_id, device_id):
    jti = client.hget(f'user:{user_id}:device_tokens', device_id)

    if jti:
        del client[f'token:{jti}']

    client.hdel(f'user:{user_id}:device_tokens', device_id)

    logger.debug(f'removed token: {jti=}, {user_id=}, {device_id=}')
    logger.debug(
        f'current_keys: {client.keys("*")}, '
        f'devices: {client.hgetall("user:{user_id}:device_tokens")}'
    )


def put_refresh_token(user_id, device_id, jti):
    client.hset(f'user:{user_id}:device_tokens', device_id, jti)

    logger.debug(f'put token with expiration: {refresh_token_ttl=}')

    client.set(f'token:{jti}', 1, ex=refresh_token_ttl)

    logger.debug(
        f'current_keys: {client.keys("*")}, '
        f'devices: {client.hgetall(f"user:{user_id}:device_tokens")}'
    )


def remove_all_user_refresh_tokens(user_id):
    token_ids = client.hvals(f'user:{user_id}:device_tokens')

    user_token_ids = [f'token:{token_id}' for token_id in token_ids]

    client.delete(*user_token_ids)

    del client[f'user:{user_id}:device_tokens']

    logger.debug(
        f'current_keys: {client.keys("*")}, '
        f'devices: {client.hgetall(f"user:{user_id}:device_tokens")}'
    )


def init(host: str, port: int, rf_token_ttl: int):
    global client, refresh_token_ttl
    client = redis.StrictRedis(host=host, port=port, decode_responses=True)
    refresh_token_ttl = rf_token_ttl


def does_refresh_token_exist(token_id: str) -> bool:
    return client.exists(f'token:{token_id}')
