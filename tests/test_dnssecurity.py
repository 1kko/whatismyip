"""DNS security posture: dnssecurity.evaluate()'s rules and fetch()'s queries.

evaluate() is pure, so its rules run on literal dicts; fetch() runs against a
fake resolver. No network.
"""

import base64

import dns.flags
import dns.rdatatype
import dns.resolver
import dns.rrset
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

import dnssecurity
import managers


def _domain(spf=(), dmarc=(), status=None, queried="example.com", zone="example.com"):
    return {
        "queried_name": queried,
        "zone": zone,
        "spf": [{"text": t, "ttl": 300} for t in spf],
        "dmarc": [
            {"text": t, "ttl": 300, "queried_name": f"_dmarc.{q}"} for t, q in dmarc
        ],
        "status": {"spf": "ok", "dmarc": "ok", **(status or {})},
    }


def _txt(*records, status="ok"):
    return {"records": list(records), "status": status}


def _raw(**over):
    raw = {
        "caa": {"records": [], "queried_name": None, "status": "noanswer"},
        "dnssec": {
            "zone": "example.com",
            "ds": "noanswer",
            "dnskey": "ok",
            "validated": False,
        },
        "dkim": {"keys": [], "status": "noanswer"},
        "mta_sts": _txt(status="nxdomain"),
        "tls_rpt": _txt(status="nxdomain"),
        "bimi": _txt(status="nxdomain"),
    }
    raw.update(over)
    return raw


def _rsa_p(bits):
    # OpenSSL will not generate a key under 1024 bits, but will load one: a
    # public key is just its numbers, and the modulus need not factor here.
    if bits < 1024:
        public = rsa.RSAPublicNumbers(65537, (1 << (bits - 1)) | 1).public_key()
    else:
        public = rsa.generate_private_key(65537, bits).public_key()
    der = public.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return base64.b64encode(der).decode()


def _state(result, check):
    return result[check]["state"]


class TestShape:
    def test_every_check_in_order(self):
        result = dnssecurity.evaluate(_domain(), _raw())
        assert tuple(result) == dnssecurity.CHECKS

    def test_no_inputs_is_all_unknown(self):
        result = dnssecurity.evaluate(None, None)
        assert {c["state"] for c in result.values()} == {"unknown"}


class TestSpf:
    @pytest.mark.parametrize(
        "text,state",
        [
            ("v=spf1 -all", "pass"),
            ("v=spf1 include:_spf.google.com ~all", "pass"),
            ("v=spf1 redirect=_spf.example.net", "pass"),
            ("v=spf1 ?all", "warn"),
            ("v=spf1 include:x.example", "warn"),
            ("v=spf1 ptr -all", "warn"),
            ("v=spf1 +all", "fail"),
            ("v=spf1 all", "fail"),
        ],
    )
    def test_all_qualifier(self, text, state):
        assert _state(dnssecurity.evaluate(_domain(spf=[text]), _raw()), "spf") == state

    def test_none_is_fail(self):
        assert (
            _state(
                dnssecurity.evaluate(_domain(status={"spf": "noanswer"}), _raw()), "spf"
            )
            == "fail"
        )

    def test_failed_query_is_unknown(self):
        assert (
            _state(
                dnssecurity.evaluate(_domain(status={"spf": "timeout"}), _raw()), "spf"
            )
            == "unknown"
        )

    def test_two_records_at_the_apex_is_fail(self):
        result = dnssecurity.evaluate(
            _domain(spf=["v=spf1 -all", "v=spf1 ~all"]), _raw()
        )
        assert _state(result, "spf") == "fail"

    def test_subdomain_with_zone_spf_is_not_two_records(self):
        domain = _domain(
            spf=["v=spf1 -all", "v=spf1 include:x ~all"],
            queried="www.example.com",
            zone="example.com",
        )
        assert _state(dnssecurity.evaluate(domain, _raw()), "spf") == "pass"


class TestDmarc:
    @pytest.mark.parametrize(
        "text,state",
        [
            ("v=DMARC1; p=reject; rua=mailto:d@example.com", "pass"),
            ("v=DMARC1; p=quarantine; rua=mailto:d@example.com", "pass"),
            ("v=DMARC1; p=none; rua=mailto:d@example.com", "warn"),
            ("v=DMARC1; p=reject", "warn"),
            ("v=DMARC1; p=reject; pct=50; rua=mailto:d@example.com", "warn"),
            ("v=DMARC1; rua=mailto:d@example.com", "warn"),
        ],
    )
    def test_policy(self, text, state):
        domain = _domain(dmarc=[(text, "example.com")])
        assert _state(dnssecurity.evaluate(domain, _raw()), "dmarc") == state

    def test_none_is_fail(self):
        domain = _domain(status={"dmarc": "nxdomain"})
        assert _state(dnssecurity.evaluate(domain, _raw()), "dmarc") == "fail"

    def test_failed_query_is_unknown(self):
        domain = _domain(status={"dmarc": "servfail"})
        assert _state(dnssecurity.evaluate(domain, _raw()), "dmarc") == "unknown"

    def test_two_records_is_fail(self):
        domain = _domain(
            dmarc=[
                ("v=DMARC1; p=reject", "example.com"),
                ("v=DMARC1; p=none", "example.com"),
            ]
        )
        assert _state(dnssecurity.evaluate(domain, _raw()), "dmarc") == "fail"

    def test_inherited_subdomain_policy_reads_sp(self):
        domain = _domain(
            dmarc=[
                ("v=DMARC1; p=reject; sp=none; rua=mailto:d@example.com", "example.com")
            ],
            queried="www.example.com",
        )
        result = dnssecurity.evaluate(domain, _raw())
        assert _state(result, "dmarc") == "warn"
        assert "example.com" in result["dmarc"]["summary"]


class TestDkim:
    def _keys(self, *pairs):
        return {"keys": [{"selector": s, "text": t} for s, t in pairs], "status": "ok"}

    def test_2048_is_pass_with_bits(self):
        result = dnssecurity.evaluate(
            _domain(),
            _raw(dkim=self._keys(("google", f"v=DKIM1; k=rsa; p={_rsa_p(2048)}"))),
        )
        assert _state(result, "dkim") == "pass"
        assert result["dkim"]["keys"] == [
            {"selector": "google", "kind": "rsa", "bits": 2048}
        ]
        assert result["dkim"]["summary"] == "DKIM: found at google (2048-bit)"

    def test_1024_is_warn(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("s1", f"p={_rsa_p(1024)}")))
        )
        assert _state(result, "dkim") == "warn"

    def test_under_1024_is_fail(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("s1", f"p={_rsa_p(768)}")))
        )
        assert _state(result, "dkim") == "fail"

    def test_ed25519_is_pass(self):
        raw_key = (
            ed25519.Ed25519PrivateKey.generate()
            .public_key()
            .public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        )
        p = base64.b64encode(raw_key).decode()
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("k2", f"v=DKIM1; k=ed25519; p={p}")))
        )
        assert _state(result, "dkim") == "pass"

    def test_revoked_only_is_warn(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("old", "v=DKIM1; p=")))
        )
        assert _state(result, "dkim") == "warn"

    def test_dkim_unparseable_key_warns(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("s1", "p=not*base64")))
        )
        assert _state(result, "dkim") == "warn"

    def test_dkim_key_with_spaces_parses(self):
        p = _rsa_p(2048)
        spaced = " ".join(p[i : i + 60] for i in range(0, len(p), 60))
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim=self._keys(("s1", f"p={spaced}")))
        )
        assert _state(result, "dkim") == "pass"

    def test_nothing_found_is_unknown_not_fail(self):
        result = dnssecurity.evaluate(_domain(), _raw())
        assert _state(result, "dkim") == "unknown"
        assert result["dkim"]["summary"] == "DKIM: not found at the common selectors"

    def test_every_query_failed_says_so(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(dkim={"keys": [], "status": "timeout"})
        )
        assert _state(result, "dkim") == "unknown"
        assert "timeout" in result["dkim"]["summary"]


class TestCaa:
    def test_none_is_warn(self):
        assert _state(dnssecurity.evaluate(_domain(), _raw()), "caa") == "warn"

    def test_issuers_are_listed(self):
        caa = {
            "records": [
                {"flags": 0, "tag": "issue", "value": "letsencrypt.org"},
                {
                    "flags": 0,
                    "tag": "issue",
                    "value": "pki.goog; cansignhttpexchanges=yes",
                },
                {"flags": 0, "tag": "iodef", "value": "mailto:sec@example.com"},
            ],
            "queried_name": "example.com",
            "status": "ok",
        }
        result = dnssecurity.evaluate(_domain(), _raw(caa=caa))
        assert _state(result, "caa") == "pass"
        assert result["caa"]["summary"] == "CAA: letsencrypt.org, pki.goog"

    def test_failure_is_unknown(self):
        caa = {"records": [], "queried_name": None, "status": "servfail"}
        assert (
            _state(dnssecurity.evaluate(_domain(), _raw(caa=caa)), "caa") == "unknown"
        )


class TestDnssec:
    @pytest.mark.parametrize(
        "ds,dnskey,validated,state",
        [
            ("ok", "ok", True, "pass"),
            ("ok", "ok", False, "warn"),
            ("noanswer", "noanswer", False, "warn"),
            ("nxdomain", "noanswer", False, "warn"),
            ("servfail", "ok", False, "unknown"),
            ("ok", "servfail", False, "unknown"),
        ],
    )
    def test_states(self, ds, dnskey, validated, state):
        dnssec = {
            "zone": "example.com",
            "ds": ds,
            "dnskey": dnskey,
            "validated": validated,
        }
        assert (
            _state(dnssecurity.evaluate(_domain(), _raw(dnssec=dnssec)), "dnssec")
            == state
        )


class TestOptionalMail:
    @pytest.mark.parametrize(
        "check,text",
        [
            ("mta_sts", "v=STSv1; id=20240101"),
            ("tls_rpt", "v=TLSRPTv1; rua=mailto:tls@example.com"),
            ("bimi", "v=BIMI1; l=https://example.com/logo.svg"),
        ],
    )
    def test_present_is_pass_absent_is_info(self, check, text):
        assert (
            _state(dnssecurity.evaluate(_domain(), _raw(**{check: _txt(text)})), check)
            == "pass"
        )
        assert _state(dnssecurity.evaluate(_domain(), _raw()), check) == "info"

    def test_other_txt_is_absent(self):
        result = dnssecurity.evaluate(
            _domain(), _raw(mta_sts=_txt("google-site-verification=x"))
        )
        assert _state(result, "mta_sts") == "info"

    def test_failure_is_unknown(self):
        result = dnssecurity.evaluate(_domain(), _raw(bimi=_txt(status="timeout")))
        assert _state(result, "bimi") == "unknown"


class _Answer:
    def __init__(self, name, rdtype, values, ad=False):
        self.rrset = dns.rrset.from_text(name + ".", 300, "IN", rdtype, *values)
        self.response = type("R", (), {"flags": dns.flags.AD if ad else 0})()

    def __iter__(self):
        return iter(self.rrset)


class _Resolver:
    def __init__(self, records, fail=None, ad=False):
        self.records, self.fail, self.ad, self.queries = records, fail or {}, ad, []

    def resolve(self, qname, rdtype="A", *a, **k):
        name = str(qname).rstrip(".").lower()
        rdtype = dns.rdatatype.to_text(dns.rdatatype.RdataType.make(rdtype))
        self.queries.append((name, rdtype))
        if (name, rdtype) in self.fail:
            raise self.fail[name, rdtype]()
        if (name, rdtype) in self.records:
            return _Answer(name, rdtype, self.records[name, rdtype], ad=self.ad)
        raise dns.resolver.NoAnswer()


@pytest.fixture
def resolver(monkeypatch):
    def install(records, fail=None, ad=False):
        fake = _Resolver(records, fail, ad)
        monkeypatch.setattr(managers, "_recursive_resolver", lambda: fake)
        monkeypatch.setattr(dnssecurity, "_validating_resolver", lambda: fake)
        return fake

    return install


class TestCaaNames:
    def test_walks_up_to_the_registrable_domain(self):
        assert dnssecurity.caa_names("a.b.example.com", "example.com") == [
            "a.b.example.com",
            "b.example.com",
            "example.com",
        ]

    def test_without_a_registrable_domain_asks_the_name_only(self):
        assert dnssecurity.caa_names("example.com", None) == ["example.com"]


class TestFetch:
    def test_nearest_caa_wins(self, resolver):
        resolver(
            {
                ("example.com", "CAA"): ['0 issue "letsencrypt.org"'],
                ("www.example.com", "CAA"): ['0 issue "pki.goog"'],
            }
        )
        raw = dnssecurity.fetch("www.example.com", "example.com", "example.com")
        assert raw["caa"]["queried_name"] == "www.example.com"
        assert raw["caa"]["records"] == [
            {"flags": 0, "tag": "issue", "value": "pki.goog"}
        ]

    def test_a_failure_below_the_answer_makes_caa_unknown(self, resolver):
        resolver(
            {("example.com", "CAA"): ['0 issue "letsencrypt.org"']},
            fail={("www.example.com", "CAA"): dns.resolver.NoNameservers},
        )
        raw = dnssecurity.fetch("www.example.com", "example.com", "example.com")
        assert raw["caa"]["status"] == "servfail"

    def test_dnssec_reads_ds_and_the_ad_flag(self, resolver):
        resolver(
            {
                ("example.com", "DS"): [
                    "370 13 2 BE74359954660069D5C63D200C39F5603827D7DD02B56F120EE9F3A86764247C"  # noqa: E501
                ],
                ("example.com", "DNSKEY"): [
                    "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ=="  # noqa: E501
                ],
            },
            ad=True,
        )
        raw = dnssecurity.fetch("example.com", "example.com", "example.com")
        assert raw["dnssec"] == {
            "zone": "example.com",
            "ds": "ok",
            "dnskey": "ok",
            "validated": True,
        }

    def test_dkim_asks_every_selector_and_keeps_keys(self, resolver):
        fake = resolver(
            {("google._domainkey.example.com", "TXT"): ['"v=DKIM1; k=rsa; " "p=AAAA"']}
        )
        raw = dnssecurity.fetch("example.com", "example.com", "example.com")
        asked = {q for q, t in fake.queries if t == "TXT" and "._domainkey." in q}
        assert asked == {
            f"{s}._domainkey.example.com" for s in dnssecurity.DKIM_SELECTORS
        }
        assert raw["dkim"] == {
            "keys": [{"selector": "google", "text": "v=DKIM1; k=rsa; p=AAAA"}],
            "status": "ok",
        }

    def test_dkim_all_failed_is_the_failure(self, resolver):
        fail = {
            (f"{s}._domainkey.example.com", "TXT"): dns.resolver.LifetimeTimeout
            for s in dnssecurity.DKIM_SELECTORS
        }
        resolver({}, fail=fail)
        raw = dnssecurity.fetch("example.com", "example.com", "example.com")
        assert raw["dkim"]["status"] == "timeout"

    def test_optional_txt_names(self, resolver):
        resolver({("_mta-sts.example.com", "TXT"): ['"v=STSv1; id=1"']})
        raw = dnssecurity.fetch("example.com", "example.com", "example.com")
        assert raw["mta_sts"] == {"records": ["v=STSv1; id=1"], "status": "ok"}
        assert raw["tls_rpt"]["status"] == "noanswer"

    def test_end_to_end_is_gradable(self, resolver):
        resolver({})
        raw = dnssecurity.fetch("example.com", "example.com", "example.com")
        result = dnssecurity.evaluate(None, raw)
        assert tuple(result) == dnssecurity.CHECKS
