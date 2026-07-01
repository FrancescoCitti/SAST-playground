"""Application configuration.

This module intentionally hardcodes credentials to exercise the secret
scanners. Real applications must read secrets from the environment or a secrets
manager — never from source.
"""

import os

# VULN #4: Hardcoded secret.
# Expected tool(s): Gitleaks (full-history scan), Semgrep (p/secrets + the
# custom `custom-hardcoded-secret` rule). A high-entropy, vendor-prefixed token
# is used so the entropy/regex detectors reliably fire.
AWS_SECRET_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # noqa
STRIPE_API_KEY = "sk_live_4eC39HqLyjWDarjtT1zdp7dcStripeKeyExample01"  # noqa

# A non-secret default, for contrast — scanners should NOT flag this.
DATABASE_PATH = os.environ.get("DATABASE_PATH", "app.db")
