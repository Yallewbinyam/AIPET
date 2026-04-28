# =============================================================
# AIPET X -- Alembic environment
#
# This file is run by every alembic command (upgrade, downgrade,
# revision, current, ...). It does three jobs:
#   1. Pulls in the SAME db.metadata the live app uses, so
#      autogenerate compares against the real model graph.
#   2. Builds the SQLAlchemy URL from the SAME DATABASE_URL env
#      var the Flask app reads in dashboard/backend/config.py --
#      no surprise of pointing at a different database.
#   3. Loads the app factory in a way that registers every
#      blueprint's models (otherwise db.metadata is partially
#      empty and the autogenerate output silently misses tables).
# =============================================================

from __future__ import annotations
import os
import pathlib
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool
from alembic import context

# Make sure the project root is on sys.path so `from dashboard.backend...`
# imports resolve when alembic is invoked from any working directory.
ROOT = pathlib.Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

# Load .env so DATABASE_URL is set when alembic is run from a fresh shell
try:
    from dotenv import load_dotenv
    load_dotenv(ROOT / ".env")
except Exception:
    pass

# Alembic Config object, with access to values from alembic.ini.
config = context.config

# Standard alembic logging from alembic.ini
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ---------------------------------------------------------------
# Build the SQLAlchemy URL.
#
# Two-role least-privilege convention (set up during PLB-1):
#   * aipet_user  -- application role; connects to aipet_db with the
#                    privileges the running Flask app needs. NO CREATEDB.
#                    Used in DATABASE_URL.
#   * aipet_admin -- migration role; LOGIN + CREATEDB; inherits from
#                    aipet_user for schema access. Used in
#                    ALEMBIC_DATABASE_URL.
#
# Priority order:
#   1. ALEMBIC_DATABASE_URL  -- the migration-role URL (preferred)
#   2. DATABASE_URL          -- fall back to the app role (works for
#                               upgrade/stamp; fails on CREATE DATABASE)
#   3. alembic.ini placeholder -- will fail loudly
#
# In dev:
#   ALEMBIC_DATABASE_URL=postgresql://aipet_admin:aipet_admin_password@localhost:5433/aipet_db
# Production: replace the placeholder password with a real secret.
# ---------------------------------------------------------------
db_url = (
    os.environ.get("ALEMBIC_DATABASE_URL")
    or os.environ.get("DATABASE_URL")
    or config.get_main_option("sqlalchemy.url")
)
# Heroku-style postgres:// -> postgresql:// fix-up to match the app
if db_url and db_url.startswith("postgres://"):
    db_url = db_url.replace("postgres://", "postgresql://", 1)
config.set_main_option("sqlalchemy.url", db_url or "")

# ---------------------------------------------------------------
# Pull db.metadata from the live app. We MUST import the app
# factory (or at least every model module) so all
# `class X(db.Model): ...` definitions register on db.metadata
# before alembic introspects it. Importing the factory is the
# safe one-liner because it triggers the same blueprint
# registrations as the running server.
# ---------------------------------------------------------------
# Setting RUNNING_UNDER_ALEMBIC lets the app skip side-effects we
# don't want during migrations (currently nothing -- placeholder
# for future extension).
os.environ.setdefault("RUNNING_UNDER_ALEMBIC", "1")

from dashboard.backend.app_cloud import create_app  # noqa: E402
from dashboard.backend.models import db             # noqa: E402

# create_app() runs db.create_all() inside an app context; we want
# to AVOID that during alembic since alembic itself manages schema.
# But the side-effect of importing the factory (registering all
# blueprints / model modules) is what we want. We therefore call
# create_app() but immediately use only its db.metadata.
_app = create_app()
target_metadata = db.metadata


def run_migrations_offline() -> None:
    """'Offline' mode -- emits SQL to stdout, no DB connection."""
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        compare_type=True,
        compare_server_default=True,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """'Online' mode -- connects to the DB and runs migrations."""
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # PLB-1: catch column-type and default drift during autogen
            compare_type=True,
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
