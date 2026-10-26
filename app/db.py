"""Database engine and session handling (SQLAlchemy 2.0 style)."""

from collections.abc import Iterator
from pathlib import Path

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool


class Base(DeclarativeBase):
    pass


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///") and not url.endswith(":memory:"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    kwargs: dict[str, object] = {"connect_args": {"check_same_thread": False}}
    if url.endswith(":memory:"):
        kwargs["poolclass"] = StaticPool  # one shared in-memory database
    engine = create_engine(url, **kwargs)

    @event.listens_for(engine, "connect")
    def _fk_on(dbapi_conn, _record):  # type: ignore[no-untyped-def]
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA foreign_keys=ON")
        cur.close()

    return engine


class Database:
    def __init__(self, url: str) -> None:
        self.engine = make_engine(url)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)

    def create_all(self) -> None:
        from app import models  # noqa: F401  (register tables)

        Base.metadata.create_all(self.engine)

    def drop_all(self) -> None:
        Base.metadata.drop_all(self.engine)

    def session(self) -> Iterator[Session]:
        with self.sessionmaker() as s:
            yield s
