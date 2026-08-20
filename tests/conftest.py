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

import sys  # noqa: E402  (must follow the env vars above)

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def reset_security_state():
    """Clear the rate limiter and ban list around every test.

    The suite drives hundreds of requests through one TestClient in a few
    seconds, and the lookup surface is rate limited with a ban on breach. Without
    this, whichever module first exceeds the limit bans "testclient" and every
    test after it — in any module — gets a 403 instead of a page.

    Read out of sys.modules rather than imported: the pure-unit modules
    (gazetteer, projection, view model) never touch the app, and importing main
    here just to clear it would load the GeoIP database into every one of their
    runs.
    """

    def clear():
        main = sys.modules.get("main")
        if main is None:
            return
        main.rate_limiter.request_history.clear()
        main.ip_ban_manager.banned_ips.clear()

    clear()
    yield
    clear()
