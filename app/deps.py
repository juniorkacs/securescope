"""Shared FastAPI dependencies."""

from collections.abc import Iterator
from typing import Annotated

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from app.db import Database


def get_database(request: Request) -> Database:
    db: Database = request.app.state.database
    return db


def get_db(database: Annotated[Database, Depends(get_database)]) -> Iterator[Session]:
    yield from database.session()


DB = Annotated[Session, Depends(get_db)]
