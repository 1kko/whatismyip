"""Test environment.

main.py reads these at import time, and load_dotenv() does not override what is
already set. Any test module that imports main therefore has to see them first —
conftest is the only place guaranteed to run before every test module, so the
suite no longer depends on which file pytest happens to collect first.
"""

import os

os.environ["ADMIN_API_KEY"] = "test-secret-key"
os.environ["TRUSTED_PROXIES"] = "127.0.0.1,10.0.0.1"
os.environ["BANNED_IPS_FILE"] = "/tmp/test_banned_ips.json"
os.environ["GEO_RULES_FILE"] = "/tmp/test_geo_rules.json"
