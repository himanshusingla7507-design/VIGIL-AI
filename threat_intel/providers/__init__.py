"""Registry of threat intelligence providers."""
from __future__ import annotations

from typing import Dict, List
from threat_intel.providers.base import BaseThreatProvider
from threat_intel.providers.cert_in import CERTInProvider
from threat_intel.providers.openphish import OpenPhishProvider
from threat_intel.providers.phishing_database import PhishingDatabaseProvider
from threat_intel.providers.phishtank import PhishTankProvider
from threat_intel.providers.urlhaus import URLhausProvider


def get_default_providers() -> List[BaseThreatProvider]:
    """Return configured provider instances in priority order."""
    return [
        URLhausProvider(),
        PhishingDatabaseProvider(),
        OpenPhishProvider(),
        PhishTankProvider(),
        CERTInProvider(),
    ]
