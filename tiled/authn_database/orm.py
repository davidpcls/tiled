import json
import uuid as uuid_module
from enum import Enum
from typing import ClassVar

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    LargeBinary,
    Table,
    Unicode,
)
from sqlalchemy import (
    Enum as SQLEnum,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, relationship
from sqlalchemy.sql import func
from sqlalchemy.types import TypeDecorator

from .base import Base

JSONVariant = JSON().with_variant(JSONB(), "postgresql")


class PrincipalType(str, Enum):
    user = "user"
    service = "service"


class JSONList(TypeDecorator):
    impl = Unicode
    cache_ok = True

    def process_bind_param(self, value, _dialect):
        if value is None:
            return None
        if not isinstance(value, list):
            msg = "JSONList must be given a literal `list` type."
            raise TypeError(msg)
        return json.dumps(value)

    def process_result_value(self, value, _dialect):
        if value is not None:
            return json.loads(value)
        return value


class UUID(TypeDecorator):
    impl = Unicode(36)
    cache_ok = True

    def process_bind_param(self, value, _dialect):
        if value is not None:
            if not isinstance(value, uuid_module.UUID):
                msg = f"Expected uuid.UUID, got {type(value)}"
                raise ValueError(msg)
            return str(value)
        return None

    def process_result_value(self, value, _dialect):
        if value is not None:
            return uuid_module.UUID(hex=value)
        return None


class Timestamped:
    __mapper_args__: ClassVar[dict[str, bool]] = {"eager_defaults": True}

    time_created = Column(
        DateTime(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    time_updated = Column(
        DateTime(timezone=True),
        onupdate=func.now(),
        nullable=True,
    )


principal_role_association_table = Table(
    "principal_role_association",
    Base.metadata,
    Column("principal_id", Integer, ForeignKey("principals.id"), primary_key=True),
    Column("role_id", Integer, ForeignKey("roles.id"), primary_key=True),
)


class Principal(Timestamped, Base):
    __tablename__ = "principals"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uuid = Column(UUID, index=True, nullable=False, default=uuid_module.uuid4)
    type = Column(SQLEnum(PrincipalType), nullable=False)

    identities: Mapped[list["Identity"]] = relationship(back_populates="principal")
    api_keys: Mapped[list["APIKey"]] = relationship(back_populates="principal")
    roles: Mapped[list["Role"]] = relationship(
        secondary=principal_role_association_table,
        back_populates="principals",
        lazy="joined",
    )
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="principal"
    )


class Identity(Timestamped, Base):
    __tablename__ = "identities"

    id = Column(Unicode(255), primary_key=True, nullable=False)
    provider = Column(Unicode(255), primary_key=True, nullable=False)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False)
    latest_login = Column(DateTime(timezone=True), nullable=True)

    principal: Mapped[Principal] = relationship(back_populates="identities")


class Role(Timestamped, Base):
    __tablename__ = "roles"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(Unicode(255), index=True, unique=True, nullable=False)
    description = Column(Unicode(1023), nullable=True)
    scopes = Column(JSONList(511), nullable=False)
    principals: Mapped[list[Principal]] = relationship(
        secondary=principal_role_association_table, back_populates="roles"
    )


class APIKey(Timestamped, Base):
    __tablename__ = "api_keys"

    first_eight = Column(Unicode(8), primary_key=True, index=True, nullable=False)
    hashed_secret = Column(
        LargeBinary(32), primary_key=True, index=True, nullable=False
    )
    expiration_time = Column(DateTime(timezone=True), nullable=True)
    latest_activity = Column(DateTime(timezone=True), nullable=True)
    note = Column(Unicode(1023), nullable=True)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False)
    scopes = Column(JSONList(511), nullable=False)
    access_tags = Column(JSONList(511), nullable=True)

    principal: Mapped[Principal] = relationship(back_populates="api_keys", lazy="joined")


class Session(Timestamped, Base):
    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    uuid = Column(UUID, index=True, nullable=False, default=uuid_module.uuid4)
    time_last_refreshed = Column(DateTime(timezone=True), nullable=True)
    refresh_count = Column(Integer, nullable=False, default=0)
    expiration_time = Column(DateTime(timezone=True), nullable=False)
    principal_id = Column(Integer, ForeignKey("principals.id"), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    state = Column(JSONVariant, nullable=False)

    principal: Mapped[Principal] = relationship(back_populates="sessions", lazy="joined")


class PendingSession(Base):
    __tablename__ = "pending_sessions"

    hashed_device_code = Column(
        LargeBinary(32), primary_key=True, index=True, nullable=False
    )
    user_code = Column(Unicode(8), index=True, nullable=False)
    expiration_time = Column(DateTime(timezone=True), nullable=False)
    session_id = Column(Integer, ForeignKey("sessions.id"), nullable=True)
    session: Mapped[Session] = relationship(lazy="joined")


__all__ = [
    "APIKey",
    "Identity",
    "JSONList",
    "JSONVariant",
    "PendingSession",
    "Principal",
    "PrincipalType",
    "Role",
    "Session",
    "Timestamped",
    "UUID",
    "principal_role_association_table",
]
