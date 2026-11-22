"""Database package (Stage 8).

Importing this package registers every SQLAlchemy mapping, which is required
before ``db.create_all()`` can build the schema. The application factory imports
``configure_database`` from here after binding the ``db`` extension, and the
routes/services import the entities from ``models.database_models``.

    from models import User, ScanHistory, ModelInformation, configure_database
"""
from __future__ import annotations

from models.database_models import (
    RISK_LEVELS,
    ROLES,
    PREDICTIONS,
    ModelInformation,
    ScanHistory,
    User,
    configure_database,
    iso_utc,
    utc_value,
    utcnow,
)

__all__ = [
    "User", "ScanHistory", "ModelInformation", "configure_database",
    "PREDICTIONS", "RISK_LEVELS", "ROLES",
    "iso_utc", "utc_value", "utcnow",
]
