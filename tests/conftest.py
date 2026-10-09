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
# The app lifespan starts the scheduler and fetches what data/ lacks (GeoLite2,
# the public suffix list), and every `with TestClient(app)` runs that lifespan.
# Off, it does neither, so no lifespan downloads anything. Importing main
# starts and fetches nothing in any case (tests/test_boot.py).
os.environ["BACKGROUND_REFRESH_ENABLED"] = "false"
# Spamhaus allows one reputation download a day: no test run may make it, even
# from a lifespan test that starts a real scheduler. Off, the lookup responses
# are exactly what they were before the feature; test_reputation.py builds
# enabled managers over synthetic lists of its own.
os.environ["REPUTATION_ENABLED"] = "false"

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
