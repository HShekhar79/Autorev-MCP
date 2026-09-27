import os

from dotenv import load_dotenv
from sqlalchemy import create_engine
from sqlalchemy.orm import declarative_base, sessionmaker


# -----------------------------------------------------------------------------
# Environment
# -----------------------------------------------------------------------------

load_dotenv()


DATABASE_URL = os.getenv(
    "ARISE_DATABASE_URL",
    "sqlite:///./arise.db",
)


# -----------------------------------------------------------------------------
# Engine configuration
# -----------------------------------------------------------------------------

connect_args = {}

if DATABASE_URL.startswith("sqlite"):
    # Required for SQLite when database sessions may be accessed
    # across FastAPI worker/request threads.
    connect_args = {
        "check_same_thread": False,
    }


engine = create_engine(
    DATABASE_URL,
    connect_args=connect_args,
    pool_pre_ping=True,
)


# -----------------------------------------------------------------------------
# Session factory
# -----------------------------------------------------------------------------

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
)


# -----------------------------------------------------------------------------
# Declarative base
# -----------------------------------------------------------------------------

Base = declarative_base()


# -----------------------------------------------------------------------------
# FastAPI database dependency
# -----------------------------------------------------------------------------

def get_db():
    """
    Create one database session for a request and guarantee that
    the session is closed afterwards.
    """

    db = SessionLocal()

    try:
        yield db
    finally:
        db.close()


# -----------------------------------------------------------------------------
# Database initialization
# -----------------------------------------------------------------------------

def init_db():
    """
    Initialize database tables.

    Models are imported here so SQLAlchemy knows about them before
    create_all() runs.
    """

    import models  # noqa: F401

    Base.metadata.create_all(bind=engine)