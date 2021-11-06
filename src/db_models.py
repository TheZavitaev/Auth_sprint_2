import uuid
from datetime import datetime
from typing import Optional

from sqlalchemy import Boolean, Column, DateTime, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import backref, relationship

from api.v1.api_models import UserLoginRecord
from db import db


class User(db.Model):
    __tablename__ = 'users'
    __table_args__ = {'extend_existing': True}

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    email = Column(String(255), unique=True, nullable=True)
    hashed_password = Column('password', String(255), nullable=False)
    registered_at = Column(DateTime, default=datetime.utcnow, nullable=False)

    active = Column(Boolean, default=True, nullable=False)
    roles = relationship(
        'Role',
        secondary='roles_users',
        backref=backref('users', lazy='dynamic')
    )

    logins = relationship(
        'LoginRecord',
        lazy='dynamic',
        cascade='all, delete-orphan',
        backref=backref('user'),
    )

    should_change_password = Column(Boolean, default=False)

    @classmethod
    def from_credentials(cls, email, hashed_password) -> 'User':
        return cls(email=email, hashed_password=hashed_password)

    @classmethod
    def get_by_id(cls, user_id) -> Optional['User']:
        return db.session.query(cls).filter_by(id=user_id).one_or_none()

    @classmethod
    def get_user_universal(
            cls,
            email: Optional[str] = None,
    ) -> Optional['User']:
        user = db.session.query(cls).filter(cls.email == email).one_or_none()
        return user

    @property
    def permissions(self):
        permissions_set = set()
        for role in self.roles:
            permissions_set.update(role.permissions)
        return list(permissions_set)

    def __repr__(self):
        return f'<User {self.email}, active: {self.active}, registered_at: {self.registered_at.date().isoformat()}>'


class Role(db.Model):
    __tablename__ = 'roles'
    __table_args__ = {'extend_existing': True}

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    name = Column(String(80), unique=True)
    description = Column(String(255))


class RolesUsers(db.Model):
    __tablename__ = 'roles_users'
    __table_args__ = (
        UniqueConstraint('user_id', 'role_id', name='_user_role'),
        {'extend_existing': True},
    )

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    user_id = Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'))
    role_id = Column('role_id', UUID(as_uuid=True), ForeignKey('roles.id'))


class LoginRecord(db.Model):
    __tablename__ = 'login_entries'
    __table_args__ = {'extend_existing': True}

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        unique=True,
        nullable=False,
    )
    user_id = Column('user_id', UUID(as_uuid=True), ForeignKey('users.id'))
    user_agent = Column(String)
    platform = Column(String(100))
    browser = Column(String(255))
    timestamp = Column(DateTime, default=datetime.utcnow, nullable=False)
    ip = Column(String(100))

    def __init__(self, user_id, platform, browser, user_agent, ip):
        self.user_id = user_id
        self.platform = platform
        self.browser = browser
        self.user_agent = user_agent
        self.ip = ip

    def to_api_model(self) -> UserLoginRecord:
        return UserLoginRecord(
            user_agent=self.user_agent,
            platform=self.platform,
            browser=self.browser,
            timestamp=self.timestamp,
            ip=self.ip,
        )
