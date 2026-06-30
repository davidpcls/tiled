from sqlalchemy.orm import DeclarativeBase


class Base(DeclarativeBase):
    """Declarative base for authentication store models."""


__all__ = ["Base"]
