import datetime
from typing import Optional

from flask import current_app
from pydantic import BaseModel, EmailStr, Field, SecretStr, root_validator, validator


def password_field_factory():
    return Field(min_length=8, max_length=100)


class UserIn(BaseModel):
    email: EmailStr
    password: SecretStr = password_field_factory()


class UserLoginRecord(BaseModel):
    user_agent: str
    platform: Optional[str]
    browser: Optional[str]
    timestamp: datetime.datetime
    ip: str


class UserInfoOut(BaseModel):
    id: str
    email: str
    registered_at: datetime.datetime

    active: bool
    roles: list


class UserPatchIn(BaseModel):
    email: Optional[EmailStr]
    new_password_1: Optional[SecretStr]
    new_password_2: Optional[SecretStr]

    @root_validator
    def one_of(cls, values):

        if not (
            values.get('email')
            or (values.get('new_password_1') and values.get('new_password_2'))
        ):
            raise ValueError('at least one value should be present.')

        return values

    @validator('new_password_2')
    def passwords_match(cls, v, values, **kwargs):

        if 'new_password_1' in values and v != values['new_password_1']:
            raise ValueError('Passwords do not match')

        return v


class UserLoginRecordsOut(BaseModel):
    logins: list[UserLoginRecord]


class TokenGrantOut(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = 'bearer'
    expires: int = Field(
        default_factory=lambda: current_app.config["JWT_ACCESS_TOKEN_EXPIRES"]
    )


class TokenInPassword(BaseModel):
    email: EmailStr
    password: SecretStr


class TokenRevokeIn(BaseModel):
    token: str


class RoleIn(BaseModel):
    name: str
    description: str


class RoleOut(BaseModel):
    id: int
    name: str
    description: Optional[str]
