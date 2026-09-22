"""SQLAlchemy database setup."""

from collections.abc import Generator

from sqlalchemy import create_engine
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings


class Base(DeclarativeBase):
    pass


engine_kwargs: dict[str, object] = {}
if settings.DATABASE_URL.startswith("sqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
    if ":memory:" in settings.DATABASE_URL:
        engine_kwargs["poolclass"] = StaticPool

engine = create_engine(settings.DATABASE_URL, **engine_kwargs)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Generator[Session, None, None]:
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    # Imports register the models with Base.metadata before table creation.
    from app.models import detection_finding, incident, security_event, user  # noqa: F401

    Base.metadata.create_all(bind=engine)

    if settings.BOOTSTRAP_USERNAME and settings.BOOTSTRAP_PASSWORD:
        from app.api.auth import hash_password
        from app.models.user import User

        with SessionLocal() as db:
            existing = db.query(User).filter(User.username == settings.BOOTSTRAP_USERNAME).first()
            if existing is None:
                db.add(User(username=settings.BOOTSTRAP_USERNAME, password_hash=hash_password(settings.BOOTSTRAP_PASSWORD)))
                db.commit()
