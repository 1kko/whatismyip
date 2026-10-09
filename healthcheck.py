"""Container liveness probe, run by the Dockerfile's HEALTHCHECK.

Exits 0 when GET /healthz answers 200 and 1 otherwise. A bare socket connect,
which this replaces, passes for any process holding port 8000, wedged or not.

It deliberately does not read `status`: /healthz answers 200 when degraded too,
and a degraded service must not be marked unhealthy. Restarting fixes neither
a stale GeoIP build nor an RDAP registry that is down, while an unhealthy
container can fail a deploy or be restarted by whatever watches it. The
external probe (.github/workflows/healthz-probe.yml) is what reads `status`.

Standard library only: the image has no curl.
"""

import sys
import urllib.request

URL = "http://127.0.0.1:8000/healthz"
# Inside the HEALTHCHECK's own --timeout, so a hung request reports why.
TIMEOUT_SECONDS = 3


def main(url: str = URL) -> int:
    # No proxy handler from the environment: an HTTP_PROXY set for the app's
    # outbound downloads must not carry a loopback probe off the box.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        # url is the fixed loopback address above, not user input.
        with opener.open(url, timeout=TIMEOUT_SECONDS) as response:  # noqa: S310
            status = response.status
    except Exception as exc:  # HTTPError (non-2xx) included
        print(f"healthz failed: {exc}")
        return 1
    if status != 200:
        print(f"healthz answered {status}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
