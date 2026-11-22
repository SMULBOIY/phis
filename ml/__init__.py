"""Machine learning package for the Phishing Website Detection System.

Stage 3 adds:
* ``ml.url_utils``  - pure, network-free URL normalisation and grouping helpers
* ``ml.preprocess`` - dataset cleaning, deduplication and leakage-safe splitting

Both modules are imported by later stages (feature extraction, training) and by
the runtime validation layer, so that training and live inference see exactly
the same canonical URL string.
"""
from __future__ import annotations

__version__ = "0.3.0"
