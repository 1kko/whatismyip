"""Link previews: Open Graph tags, a self page titled without an IP, and HTML
for the bots that build the previews.

A link pasted into KakaoTalk, Slack or Telegram is expanded by a bot that
fetches the page and reads its og: tags. Those bots do not say "Mozilla", so
they used to get JSON and the preview came out blank; and the self page's
<title> was the visitor's own IP, which a preview would have carried into
someone else's chat. Every lookup is mocked; no test here touches the network.
"""

import copy
import re
from contextlib import contextmanager
from html import unescape
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

import main
from main import BrowserDetector, app
from viewmodel import build_view

VISITOR_IP = "118.235.14.201"
client = TestClient(app, client=(VISITOR_IP, 41234))

# The user-agents as the services send them. KakaoTalk's borrows Facebook's
# token, so the bare kakaotalk-scrap token is checked on its own below too.
KAKAOTALK = (
    "facebookexternalhit/1.1; kakaotalk-scrap/1.0; "
    "+https://devtalk.kakao.com/t/scrap/33984"
)
SLACKBOT = "Slackbot-LinkExpanding 1.0 (+https://api.slack.com/robots)"
PREVIEW_BOTS = [
    KAKAOTALK,
    SLACKBOT,
    "Twitterbot/1.0",
    "facebookexternalhit/1.1 (+http://www.facebook.com/externalhit_uatext.php)",
    "TelegramBot (like TwitterBot)",
    "WhatsApp/2.23.20.0 A",
    "Mozilla/5.0 (compatible; Discordbot/2.0; +https://discordapp.com)",
    "LinkedInBot/1.0 (compatible; Mozilla/5.0; Apache-HttpClient "
    "+http://www.linkedin.com)",
]
CHROME = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
)

VISITOR_LOCATION = {
    "ip": VISITOR_IP,
    "country_code": "KR",
    "country_name": "South Korea",
    "city_name": "Seoul",
    "lat": 37.566,
    "lon": 126.978,
    "accuracy_km": 20,
    "cidr": "118.235.0.0/16",
    "asn_name": "Korea Telecom",
    "asn_number": 4766,
    "is_private": False,
}
CERTIFICATE = {
    "subject": ((("commonName", "nasa.gov"),),),
    "issuer": ((("organizationName", "DigiCert Inc"),),),
    "notBefore": "Jun 01 00:00:00 2026 GMT",
    "notAfter": "Jun 01 00:00:00 2099 GMT",
    "subjectAltName": (("DNS", "nasa.gov"), ("DNS", "www.nasa.gov")),
}
NASA = {
    "address": "nasa.gov",
    "domain": {"a": [{"ip": "192.0.66.108", "ttl": 300}], "mx": [], "ns": []},
    "location": {
        "ip": "192.0.66.108",
        "country_code": "US",
        "country_name": "United States",
        "city_name": "San Francisco",
        "lat": 37.775,
        "lon": -122.419,
        "accuracy_km": 20,
        "cidr": "192.0.64.0/18",
        "asn_name": "Automattic, Inc",
        "asn_number": 2635,
        "is_private": False,
    },
    "whois": {"source": "rdap", "registrar": "Example Registrar"},
    "ssl": CERTIFICATE,
    "resolved_ip": "192.0.66.108",
    "reverse_dns": None,
}


@contextmanager
def mocked_lookups(gathered=NASA):
    with (
        patch(
            "main.gather",
            new_callable=AsyncMock,
            side_effect=lambda *_: copy.deepcopy(gathered),
        ),
        patch(
            "main.lookup_location",
            new_callable=AsyncMock,
            side_effect=lambda *_: dict(VISITOR_LOCATION),
        ),
        patch(
            "main.lookup_whois",
            new_callable=AsyncMock,
            return_value={"source": "rdap", "name": "KT"},
        ),
        patch("main.domain_manager.perform_reverse_lookup", return_value=None),
    ):
        yield


def _get(path, user_agent=CHROME, **headers):
    with mocked_lookups():
        return client.get(path, headers={"user-agent": user_agent, **headers})


def _head(response):
    return response.text.split("</head>")[0]


def _meta(head, attribute, name):
    found = re.search(
        rf'<meta {attribute}="{re.escape(name)}" content="([^"]*)">', head
    )
    assert found, f"no {name} in <head>"
    return unescape(found.group(1))


def _og(head, name):
    return _meta(head, "property", f"og:{name}")


def _canonical(head):
    found = re.search(r'<link rel="canonical" href="([^"]*)">', head)
    assert found, "no canonical link in <head>"
    return unescape(found.group(1))


def _title(head):
    return unescape(re.search(r"<title>(.*?)</title>", head).group(1))


def _is_html(response):
    return response.headers["content-type"].startswith("text/html")


def _is_json(response):
    return response.headers["content-type"].startswith("application/json")


class TestPreviewBots:
    """Step 3 of negotiate(): the bots that expand a shared link get the page,
    because the page is what carries the og: tags."""

    @pytest.mark.parametrize("user_agent", PREVIEW_BOTS)
    def test_each_preview_bot_counts_as_a_browser(self, user_agent):
        assert BrowserDetector.is_browser(user_agent)

    def test_the_kakaotalk_token_alone_is_enough(self):
        assert BrowserDetector.is_browser("kakaotalk-scrap/1.0")

    def test_kakaotalk_gets_html_with_og_tags(self):
        """The case the item exists for: a link shared in KakaoTalk."""
        response = _get("/nasa.gov", KAKAOTALK)
        assert response.status_code == 200
        assert _is_html(response)
        head = _head(response)
        assert _og(head, "title") == "nasa.gov — WhatIsMyIP"
        assert _og(head, "description").startswith("nasa.gov · ")
        assert _og(head, "url") == "http://testserver/nasa.gov"
        assert _og(head, "image").startswith("http://testserver/static/")
        assert _meta(head, "name", "twitter:card") == "summary"
        assert _canonical(head) == "http://testserver/nasa.gov"

    @pytest.mark.parametrize("path", ["/", "/nasa.gov"])
    def test_slackbot_gets_html(self, path):
        response = _get(path, SLACKBOT)
        assert response.status_code == 200
        assert _is_html(response)
        assert 'property="og:title"' in _head(response)

    @pytest.mark.parametrize("path", ["/", "/nasa.gov"])
    def test_format_json_still_beats_a_bot_user_agent(self, path):
        """Only the user-agent fallback learned the bots; an explicit request
        for JSON is answered with JSON whoever makes it."""
        response = _get(f"{path}?format=json", KAKAOTALK)
        assert response.status_code == 200
        assert _is_json(response)

    def test_an_accept_header_still_beats_a_bot_user_agent(self):
        response = _get("/nasa.gov", SLACKBOT, accept="application/json")
        assert _is_json(response)


class TestSelfPage:
    """`/` describes whoever opens it. A preview of a shared ip.1kko.com link
    must not carry the IP of whoever, or whatever, fetched it."""

    def test_title_is_fixed_and_carries_no_ip(self):
        head = _head(_get("/"))
        assert _title(head) == "What is my IP address? — WhatIsMyIP"

    def test_the_visitor_ip_appears_nowhere_in_the_head(self):
        """The bot sees its own IP in the body, which is harmless. The head is
        what a preview is built from, so the IP must not be anywhere in it."""
        for user_agent in (CHROME, KAKAOTALK):
            response = _get("/", user_agent)
            assert VISITOR_IP not in _head(response)
            assert VISITOR_IP in response.text  # still on the page itself

    def test_the_visitor_ip_is_the_h1(self):
        html = _get("/").text
        assert f'<h1 class="ip mono">{VISITOR_IP}</h1>' in html

    def test_og_url_and_canonical_are_the_base_url(self):
        head = _head(_get("/"))
        assert _og(head, "url") == "http://testserver/"
        assert _canonical(head) == "http://testserver/"

    def test_og_title_and_description_are_generic(self):
        head = _head(_get("/"))
        assert _og(head, "title") == _title(head)
        description = _og(head, "description")
        assert "WHOIS" in description
        assert _meta(head, "name", "description") == description


class TestLookupPage:
    def test_description_summarises_the_lookup(self):
        head = _head(_get("/nasa.gov"))
        assert (
            _og(head, "description")
            == "nasa.gov · AS2635 Automattic, Inc · United States · TLS valid"
        )
        assert _meta(head, "name", "description") == _og(head, "description")

    def test_an_ip_lookup_has_no_tls_segment(self):
        ip = {
            **NASA,
            "address": "8.8.8.8",
            "domain": {},
            "location": {
                **NASA["location"],
                "ip": "8.8.8.8",
                "asn_name": "Google LLC",
                "asn_number": 15169,
            },
            "ssl": None,
        }
        with mocked_lookups(ip):
            head = _head(client.get("/8.8.8.8", headers={"user-agent": CHROME}))
        assert (
            _og(head, "description") == "8.8.8.8 · AS15169 Google LLC · United States"
        )
        assert _canonical(head) == "http://testserver/8.8.8.8"

    def test_canonical_uses_the_public_base_url(self, monkeypatch):
        monkeypatch.setattr(main, "PUBLIC_BASE_URL", "https://ip.1kko.com")
        head = _head(_get("/nasa.gov"))
        assert _canonical(head) == "https://ip.1kko.com/nasa.gov"
        assert _og(head, "url") == "https://ip.1kko.com/nasa.gov"
        assert _og(head, "image").startswith("https://ip.1kko.com/static/")

    def test_canonical_is_the_normalised_target_without_the_query(self):
        """A host's case and ?format= do not make it a different page.
        gather() keeps the case it was given, so the canonical folds it."""
        upper = {**NASA, "address": "NASA.gov"}
        with mocked_lookups(upper):
            head = _head(
                client.get("/NASA.gov?format=html", headers={"user-agent": CHROME})
            )
        assert _canonical(head) == "http://testserver/nasa.gov"
        assert _og(head, "url") == "http://testserver/nasa.gov"

    def test_og_image_is_a_file_we_serve(self):
        head = _head(_get("/nasa.gov"))
        path = _og(head, "image").removeprefix("http://testserver/")
        assert Path(path).is_file()
        assert client.get("/" + path).status_code == 200

    def test_description_is_escaped(self):
        hostile = copy.deepcopy(NASA)
        hostile["location"]["asn_name"] = '"><script>alert(1)</script>'
        with mocked_lookups(hostile):
            head = _head(client.get("/nasa.gov", headers={"user-agent": CHROME}))
        assert "<script>alert(1)" not in head
        assert _og(head, "description") == (
            'nasa.gov · AS2635 "><script>alert(1)</script> · United States · TLS valid'
        )


class TestDescription:
    """build_view()'s summary, without the app around it."""

    def test_missing_parts_are_left_out_not_dashed(self):
        bare = {"address": "example.com", "location": {}, "domain": {}, "ssl": None}
        assert build_view(bare, is_self=False)["description"] == "example.com"

    def test_org_without_an_as_number(self):
        response = {
            "address": "example.com",
            "location": {"asn_name": "Example Org", "country_name": "Japan"},
            "domain": {},
            "ssl": None,
        }
        assert (
            build_view(response, is_self=False)["description"]
            == "example.com · Example Org · Japan"
        )

    def test_the_self_view_never_names_the_address(self):
        response = {
            "address": VISITOR_IP,
            "location": dict(VISITOR_LOCATION),
            "domain": {},
            "ssl": None,
        }
        view = build_view(response, is_self=True)
        assert VISITOR_IP not in view["title"]
        assert VISITOR_IP not in view["description"]
        assert view["canonical_path"] == ""
