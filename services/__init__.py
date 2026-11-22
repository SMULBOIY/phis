"""Domain/service layer for the Phishing Website Detection System.

Blueprints stay thin and delegate to this package:

* Stage 4  ``validation``       - live URL input boundary
* Stage 7  ``model_metadata``   - measured artefact contract and hash check
* Stage 7  ``http_security``    - CSP, headers, errors, request guard
* Stage 8  ``auth_service``     - validation, scrypt hashing, authentication
* Stage 8  ``database_service`` - schema bootstrap, status, measured seeding
* Stage 10 ``detection_service`` - full scan pipeline and audit persistence
* Stage 10 ``decision_service``  - measured thresholds -> three states
* Stage 10 ``explanation_service`` - measured importance, caveats, actions
* Stage 11 ``stats_service``      - live aggregates, history, measured metrics
* Stage 11 ``report_service``     - safe CSV export
* Stage 12 keeps all helpers in ``routes/api.py`` (no new service module)
* Stage 13+ tests and deployment helpers
"""
from __future__ import annotations

__version__ = "0.14.0"
