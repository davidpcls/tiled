import hashlib
import uuid as uuid_module
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncEngine, AsyncSession
from sqlalchemy.future import select
from sqlalchemy.orm import selectinload
from sqlalchemy.sql import func

from .base import Base
from .orm import APIKey, Identity, PendingSession, Principal, Role, Session

ALL_REVISIONS = [
    "2d1b550e12e0",
    "d829476bc173",
    "27e069ba3bf5",
    "a806cc635ab2",
    "0c705a02954c",
    "d88e91ea03f9",
    "13024b8a6b74",
    "769180ce732e",
    "c7bd2573716d",
    "4a9dfaba4a98",
    "56809bcbfcb0",
    "722ff4e4fcc7",
    "481830dd6c11",
]
REQUIRED_REVISION = ALL_REVISIONS[0]


async def create_default_roles(db: AsyncSession) -> None:
    default_roles = [
        Role(
            name="user",
            description="Default Role for users.",
            scopes=[
                "read:metadata",
                "read:data",
                "create:node",
                "write:metadata",
                "write:data",
                "delete:revision",
                "delete:node",
                "create:apikeys",
                "revoke:apikeys",
            ],
        ),
        Role(
            name="admin",
            description="Role with elevated privileges.",
            scopes=[
                "read:metadata",
                "read:data",
                "create:node",
                "register",
                "write:metadata",
                "write:data",
                "delete:revision",
                "delete:node",
                "admin:apikeys",
                "read:principals",
                "write:principals",
                "metrics",
                "read:webhooks",
                "write:webhooks",
            ],
        ),
    ]

    roles_result = await db.execute(select(Role.name))
    existing_role_names = set(roles_result.scalars().all())
    roles_to_add = [role for role in default_roles if role.name not in existing_role_names]
    if roles_to_add:
        db.add_all(roles_to_add)
        await db.commit()


async def initialize_database(engine: AsyncEngine) -> None:
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    async with AsyncSession(engine) as db:
        await create_default_roles(db)


async def purge_expired(db: AsyncSession, cls) -> int:
    now = datetime.now(timezone.utc)
    num_expired = 0
    result = await db.execute(
        select(cls)
        .filter(cls.expiration_time.is_not(None))
        .filter(cls.expiration_time < now)
    )
    for obj in result.scalars():
        num_expired += 1
        await db.delete(obj)
    if num_expired:
        await db.commit()
    return num_expired


async def create_user(db: AsyncSession, identity_provider: str, id: str) -> Principal:
    user_role = (await db.execute(select(Role).filter(Role.name == "user"))).scalar()
    if user_role is None:
        msg = "User role is missing from Roles table"
        raise RuntimeError(msg)
    principal = Principal(type="user", roles=[user_role])
    db.add(principal)
    await db.commit()
    db.add(Identity(provider=identity_provider, id=id, principal_id=principal.id))
    await db.commit()
    refreshed = (
        await db.execute(
            select(Principal)
            .filter(Principal.id == principal.id)
            .options(selectinload(Principal.identities))
        )
    ).scalar()
    if refreshed is None:
        msg = "Principal not found after creation"
        raise RuntimeError(msg)
    return refreshed


async def create_service(db: AsyncSession, role: str) -> Principal:
    role_ = (await db.execute(select(Role).filter(Role.name == role))).scalar()
    if role_ is None:
        msg = f"Role named {role!r} is not found"
        raise ValueError(msg)
    principal = Principal(type="service", roles=[role_])
    db.add(principal)
    await db.commit()
    return principal


async def lookup_valid_session(db: AsyncSession, session_id: str) -> Session | None:
    if isinstance(session_id, int):
        return None
    session = (
        await db.execute(
            select(Session)
            .options(
                selectinload(Session.principal).selectinload(Principal.roles),
                selectinload(Session.principal).selectinload(Principal.identities),
            )
            .filter(Session.uuid == uuid_module.UUID(hex=session_id))
        )
    ).scalar()
    if session is None:
        return None
    if session.expiration_time is not None and session.expiration_time.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        await db.delete(session)
        await db.commit()
        return None
    return session


async def lookup_valid_pending_session_by_device_code(
    db: AsyncSession, device_code: bytes
) -> PendingSession | None:
    hashed_device_code = hashlib.sha256(device_code).digest()
    pending = (
        await db.execute(
            select(PendingSession)
            .filter(PendingSession.hashed_device_code == hashed_device_code)
            .options(
                selectinload(PendingSession.session)
                .selectinload(Session.principal)
                .selectinload(Principal.identities),
            )
        )
    ).scalar()
    if pending is None:
        return None
    if pending.expiration_time is not None and pending.expiration_time.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        await db.delete(pending)
        await db.commit()
        return None
    return pending


async def lookup_valid_pending_session_by_user_code(
    db: AsyncSession, user_code: str
) -> PendingSession | None:
    pending = (
        await db.execute(select(PendingSession).filter(PendingSession.user_code == user_code))
    ).scalar()
    if pending is None:
        return None
    if pending.expiration_time is not None and pending.expiration_time.replace(
        tzinfo=timezone.utc
    ) < datetime.now(timezone.utc):
        await db.delete(pending)
        await db.commit()
        return None
    return pending


async def make_admin_by_identity(
    db: AsyncSession, identity_provider: str, id: str
) -> Principal:
    identity = (
        await db.execute(
            select(Identity)
            .options(selectinload(Identity.principal).selectinload(Principal.roles))
            .filter(Identity.id == id)
            .filter(Identity.provider == identity_provider)
        )
    ).scalar()
    principal = await create_user(db, identity_provider, id) if identity is None else identity.principal
    for role in principal.roles:
        if role.name == "admin":
            return principal
    admin_role = (await db.execute(select(Role).filter(Role.name == "admin"))).scalar()
    if admin_role is None:
        msg = "Admin role is missing from Roles table"
        raise RuntimeError(msg)
    principal.roles.append(admin_role)
    await db.commit()
    return principal


async def lookup_valid_api_key(db: AsyncSession, secret: bytes) -> APIKey | None:
    now = datetime.now(timezone.utc)
    hashed_secret = hashlib.sha256(secret).digest()
    api_key = (
        await db.execute(
            select(APIKey)
            .options(
                selectinload(APIKey.principal).selectinload(Principal.roles),
                selectinload(APIKey.principal).selectinload(Principal.identities),
                selectinload(APIKey.principal).selectinload(Principal.sessions),
            )
            .filter(APIKey.first_eight == secret.hex()[:8])
            .filter(APIKey.hashed_secret == hashed_secret)
        )
    ).scalar()
    if api_key is None:
        return None
    if (api_key.expiration_time is not None) and (
        api_key.expiration_time.replace(tzinfo=timezone.utc) < now
    ):
        await db.delete(api_key)
        await db.commit()
        return None
    if api_key.principal is None:
        await db.delete(api_key)
        await db.commit()
        return None
    return api_key


async def latest_principal_activity(
    db: AsyncSession, principal: Principal
) -> datetime | None:
    latest_identity_activity = (
        await db.execute(
            select(func.max(Identity.latest_login)).filter(Identity.principal_id == principal.id)
        )
    ).scalar()
    latest_session_activity = (
        await db.execute(
            select(func.max(Session.time_last_refreshed)).filter(Session.principal_id == principal.id)
        )
    ).scalar()
    latest_api_key_activity = (
        await db.execute(
            select(func.max(APIKey.latest_activity)).filter(APIKey.principal_id == principal.id)
        )
    ).scalar()
    all_activity = [latest_identity_activity, latest_api_key_activity, latest_session_activity]
    if all(t is None for t in all_activity):
        return None
    return max(t for t in all_activity if t is not None)


async def get_or_create_principal(
    db: AsyncSession, identity_provider: str, id: str
) -> Principal:
    identity = (
        await db.execute(
            select(Identity)
            .options(
                selectinload(Identity.principal).selectinload(Principal.roles),
                selectinload(Identity.principal).selectinload(Principal.identities),
            )
            .filter(Identity.id == id)
            .filter(Identity.provider == identity_provider)
        )
    ).scalar()
    if identity is not None:
        identity.latest_login = datetime.now(timezone.utc)
        await db.commit()
        return identity.principal
    return await create_user(db, identity_provider, id)


__all__ = [
    "ALL_REVISIONS",
    "REQUIRED_REVISION",
    "create_default_roles",
    "create_service",
    "create_user",
    "get_or_create_principal",
    "initialize_database",
    "latest_principal_activity",
    "lookup_valid_api_key",
    "lookup_valid_pending_session_by_device_code",
    "lookup_valid_pending_session_by_user_code",
    "lookup_valid_session",
    "make_admin_by_identity",
    "purge_expired",
]
