"""A broken TLS certificate is reported with the reason, not as "no certificate".

SSLManager used to turn every exception from its verifying handshake into None,
so an expired, self-signed, wrong-host or chain-incomplete certificate all read
as "no certificate" on the page and "No TLS certificate served" over MCP, and
the expired/host-mismatch rendering in viewmodel.py never fired on real data.

The ssl layer is scripted here (socket + SSLContext mocks) for each failure
mode, with real DER certificates built by `cryptography`, so the x509 path is
exercised without the network. TestRealHandshake then runs the real OpenSSL
verifier against a TLS server on loopback, to prove the verify codes the mocks
assume are the ones OpenSSL actually reports.
"""

import datetime
import logging
import socket
import ssl
import threading
from contextlib import contextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from fastapi.testclient import TestClient

import main
import managers
from main import app
from managers import SSLManager
from viewmodel import _cert_expiry

HOST = "example.com"
IP = "93.184.216.34"
NOW = datetime.datetime.now(datetime.timezone.utc)
DAY = datetime.timedelta(days=1)


# --- certificates ---------------------------------------------------------------


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _name(common_name, org=None):
    attrs = [x509.NameAttribute(NameOID.COUNTRY_NAME, "US")]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    attrs.append(x509.NameAttribute(NameOID.COMMON_NAME, common_name))
    return x509.Name(attrs)


def _issue(
    common_name,
    key,
    *,
    issuer=None,
    issuer_key=None,
    sans=(),
    ca=False,
    org=None,
    not_before=None,
    not_after=None,
):
    """A certificate shaped like a real one, extensions included: Python 3.13+
    verifies with VERIFY_X509_STRICT, which rejects a CA without a key usage or
    a leaf without an authority key identifier before it ever reaches the
    check a test means to exercise. No issuer means self-signed."""
    signer = issuer_key or key
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name, org))
        .issuer_name(issuer.subject if issuer is not None else _name(common_name, org))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(not_before or NOW - DAY)
        .not_valid_after(not_after or NOW + 90 * DAY)
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical=False,
        )
    )
    if ca:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    else:
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False
        )
    if sans:
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(name) for name in sans]),
            critical=False,
        )
    return builder.sign(signer, hashes.SHA256())


def _der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


@pytest.fixture(scope="module")
def pki():
    """A root, an intermediate under it, and the leaves each failure needs."""
    root_key, inter_key, leaf_key = _key(), _key(), _key()
    root = _issue("Test Root CA", root_key, ca=True, org="Test PKI")
    inter = _issue(
        "Test Intermediate",
        inter_key,
        issuer=root,
        issuer_key=root_key,
        ca=True,
        org="Test PKI",
    )

    def leaf(sans=(HOST, f"www.{HOST}"), issuer=root, issuer_key=root_key, **kw):
        return _issue(
            sans[0] if sans else HOST,
            leaf_key,
            issuer=issuer,
            issuer_key=issuer_key,
            sans=sans,
            **kw,
        )

    return SimpleNamespace(
        root=root,
        root_key=root_key,
        leaf_key=leaf_key,
        valid=leaf(),
        expired=leaf(not_before=NOW - 120 * DAY, not_after=NOW - 30 * DAY),
        wrong_host=leaf(sans=("other.example.net",)),
        # Signed by the intermediate, which the server then leaves out.
        chain_incomplete=leaf(issuer=inter, issuer_key=inter_key),
        # What `openssl req -x509` makes: its own CA, trusted by nobody.
        self_signed=_issue(
            HOST, leaf_key, sans=(HOST, f"www.{HOST}"), ca=True, org="Self Signed"
        ),
    )


# --- a scripted ssl layer ---------------------------------------------------------


def _tls_socket(peercert=None, der=None):
    """What wrap_socket hands back: a context manager over an SSLSocket."""
    tls = MagicMock(name="SSLSocket")
    tls.__enter__.return_value = tls
    tls.getpeercert.side_effect = lambda binary_form=False: (
        der if binary_form else (peercert or {})
    )
    tls.version.return_value = "TLSv1.3"
    tls.cipher.return_value = ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256)
    return tls


def _verify_failure(code, message):
    """SSLCertVerificationError as _ssl.c raises it."""
    exc = ssl.SSLCertVerificationError(
        1,
        "[SSL: CERTIFICATE_VERIFY_FAILED] certificate verify failed: "
        f"{message} (_ssl.c:1082)",
    )
    exc.reason = "CERTIFICATE_VERIFY_FAILED"
    exc.library = "SSL"
    exc.verify_code = code
    exc.verify_message = message
    return exc


@contextmanager
def scripted_tls(*handshakes, connect_error=None):
    """Each SSLContext.wrap_socket call takes the next item of `handshakes`:
    an exception to raise, or a socket from _tls_socket() to hand back.

    Name resolution is booby-trapped for the duration: the re-handshake must
    reuse the IP the caller verified, never look the hostname up again.
    """
    seen = SimpleNamespace(sockets=[], contexts=[])
    pending = list(handshakes)

    def new_socket(*args, **kwargs):
        sock = MagicMock(name=f"socket{len(seen.sockets)}")
        if connect_error is not None:
            sock.connect.side_effect = connect_error
        seen.sockets.append(sock)
        return sock

    def new_context(*args, **kwargs):
        ctx = MagicMock(name=f"context{len(seen.contexts)}")
        ctx.wrap_socket.side_effect = [pending.pop(0)]
        seen.contexts.append(ctx)
        return ctx

    def no_dns(*args, **kwargs):
        raise AssertionError("the TLS lookup must not resolve names")

    with (
        patch("managers.socket.socket", side_effect=new_socket),
        patch("managers.ssl.create_default_context", side_effect=new_context),
        patch("socket.getaddrinfo", side_effect=no_dns),
        patch("socket.gethostbyname", side_effect=no_dns),
    ):
        yield seen


def _untrusted(pki_cert, code, message, host=HOST):
    """get_ssl_info for a certificate the verifying handshake rejected."""
    with scripted_tls(
        _verify_failure(code, message), _tls_socket(der=_der(pki_cert))
    ) as seen:
        return SSLManager.get_ssl_info(host, verified_ip=IP), seen


VERIFIED_PEERCERT = {
    "subject": ((("commonName", HOST),),),
    "issuer": ((("countryName", "US"),), (("organizationName", "Let's Encrypt"),)),
    "version": 3,
    "serialNumber": "0ABCDEF0",
    "notBefore": "Jun  1 00:00:00 2026 GMT",
    "notAfter": "Dec 31 23:59:59 2099 GMT",
    "subjectAltName": (("DNS", HOST), ("DNS", f"www.{HOST}")),
    "OCSP": ("http://r3.o.lencr.org",),
}


# --- SSLManager -------------------------------------------------------------------


class TestTrustedCertificate:
    def test_keeps_every_existing_key_and_says_it_is_trusted(self):
        with scripted_tls(_tls_socket(peercert=VERIFIED_PEERCERT)) as seen:
            info = SSLManager.get_ssl_info(HOST, verified_ip=IP)
        for key, value in VERIFIED_PEERCERT.items():
            assert info[key] == value
        assert info["protocol"] == "TLSv1.3"
        assert info["cipher"]["name"] == "TLS_AES_256_GCM_SHA384"
        assert info["trusted"] is True
        assert info["verify_error"] is None
        assert info["hostname_match"] is True
        # One handshake, the verifying one: no second, unverified read.
        assert len(seen.sockets) == len(seen.contexts) == 1


class TestUntrustedCertificate:
    @pytest.mark.parametrize(
        "cert_name, code, message, reason",
        [
            ("expired", 10, "certificate has expired", "expired"),
            ("self_signed", 18, "self-signed certificate", "self_signed"),
            (
                "wrong_host",
                62,
                "Hostname mismatch, certificate is not valid for 'example.com'.",
                "hostname_mismatch",
            ),
            (
                "chain_incomplete",
                20,
                "unable to get local issuer certificate",
                "chain_incomplete",
            ),
            (
                "chain_incomplete",
                21,
                "unable to verify the first certificate",
                "chain_incomplete",
            ),
            (
                "self_signed",
                19,
                "self-signed certificate in certificate chain",
                "untrusted_root",
            ),
            ("valid", 9, "certificate is not yet valid", "not_yet_valid"),
            # Anything without a reason of its own keeps OpenSSL's code and text.
            ("valid", 26, "unsupported certificate purpose", "other"),
        ],
    )
    def test_the_certificate_comes_back_with_why_it_failed(
        self, pki, cert_name, code, message, reason
    ):
        info, _ = _untrusted(getattr(pki, cert_name), code, message)
        assert info["trusted"] is False
        assert info["verify_error"] == {
            "code": code,
            "message": message,
            "reason": reason,
        }
        # Still a certificate: the same keys getpeercert() would have given.
        assert info["subject"]
        assert info["issuer"]
        assert info["notAfter"]
        assert info["protocol"] == "TLSv1.3"
        assert info["cipher"]["bits"] == 256

    def test_rehandshake_reuses_the_verified_ip_without_verification(self, pki):
        info, seen = _untrusted(pki.expired, 10, "certificate has expired")
        assert info["trusted"] is False
        # Both handshakes went to the IP the caller already vetted with
        # is_safe_ip(); the hostname only rides along as SNI.
        assert [s.connect.call_args.args for s in seen.sockets] == [
            ((IP, 443),),
            ((IP, 443),),
        ]
        for ctx in seen.contexts:
            assert ctx.wrap_socket.call_args.kwargs["server_hostname"] == HOST
        relaxed = seen.contexts[1]
        assert relaxed.check_hostname is False
        assert relaxed.verify_mode == ssl.CERT_NONE
        assert relaxed.minimum_version == ssl.TLSVersion.TLSv1_2
        # Same per-socket timeout as the verifying handshake.
        assert (
            seen.sockets[1].settimeout.call_args == seen.sockets[0].settimeout.call_args
        )

    def test_expiry_is_read_from_the_certificate(self, pki):
        info, _ = _untrusted(pki.expired, 10, "certificate has expired")
        _, days_left = _cert_expiry(info)
        assert days_left is not None and days_left < 0

    def test_hostname_match_reflects_the_certificate(self, pki):
        mismatch, _ = _untrusted(
            pki.wrong_host,
            62,
            "Hostname mismatch, certificate is not valid for 'example.com'.",
        )
        assert mismatch["hostname_match"] is False
        # OpenSSL stops at the chain before it gets to the name, so the name
        # is checked against the SANs here instead.
        self_signed, _ = _untrusted(pki.self_signed, 18, "self-signed certificate")
        assert self_signed["hostname_match"] is True
        www, _ = _untrusted(
            pki.self_signed, 18, "self-signed certificate", host=f"www.{HOST}"
        )
        assert www["hostname_match"] is True
        elsewhere, _ = _untrusted(
            pki.self_signed, 18, "self-signed certificate", host="example.org"
        )
        assert elsewhere["hostname_match"] is False

    def test_wildcard_covers_exactly_one_label(self):
        wildcard = _issue("*.example.com", _key(), sans=("*.example.com",), ca=True)
        hits = {
            host: _untrusted(wildcard, 18, "self-signed certificate", host=host)[0][
                "hostname_match"
            ]
            for host in ("www.example.com", "example.com", "a.b.example.com")
        }
        assert hits == {
            "www.example.com": True,
            "example.com": False,
            "a.b.example.com": False,
        }

    def test_verdict_survives_a_failed_rehandshake(self):
        with scripted_tls(
            _verify_failure(10, "certificate has expired"), TimeoutError("timed out")
        ):
            info = SSLManager.get_ssl_info(HOST, verified_ip=IP)
        assert info["trusted"] is False
        assert info["verify_error"]["reason"] == "expired"
        assert info["hostname_match"] is None  # never got to read the names
        assert "issuer" not in info

    def test_verify_failure_is_logged_at_info_not_error(self, pki, caplog):
        with caplog.at_level(logging.DEBUG):
            _untrusted(
                pki.chain_incomplete, 20, "unable to get local issuer certificate"
            )
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        assert any(
            r.levelno == logging.INFO and "unable to get local issuer" in r.getMessage()
            for r in caplog.records
        )


class TestUnreachable:
    @pytest.mark.parametrize(
        "error, reason",
        [
            (ConnectionRefusedError(61, "Connection refused"), "connection refused"),
            (TimeoutError("timed out"), "timed out"),
            (OSError(65, "No route to host"), "no route to host"),
        ],
    )
    def test_port_443_unreachable_is_an_explicit_error(self, error, reason, caplog):
        with caplog.at_level(logging.DEBUG), scripted_tls(connect_error=error) as seen:
            info = SSLManager.get_ssl_info(HOST, verified_ip=IP)
        assert info == {"error": "port 443 unreachable", "reason": reason}
        assert seen.contexts == []  # nothing to shake hands with
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]

    @pytest.mark.parametrize(
        "error, reason",
        [
            (
                TimeoutError("_ssl.c:983: The handshake operation timed out"),
                "timed out",
            ),
            (
                ssl.SSLError(1, "[SSL: WRONG_VERSION_NUMBER] wrong version number"),
                "wrong version number",
            ),
            (
                ConnectionResetError(54, "Connection reset by peer"),
                "connection reset by peer",
            ),
        ],
    )
    def test_a_handshake_that_never_completes_says_so(self, error, reason):
        if isinstance(error, ssl.SSLError):
            error.reason = "WRONG_VERSION_NUMBER"
        with scripted_tls(error):
            info = SSLManager.get_ssl_info(HOST, verified_ip=IP)
        assert info == {"error": "TLS handshake failed", "reason": reason}

    def test_no_verified_ip_still_means_no_lookup(self):
        with scripted_tls() as seen:
            assert SSLManager.get_ssl_info(HOST, verified_ip=None) is None
        assert seen.sockets == []


class TestDerParsing:
    def test_matches_what_getpeercert_returns(self, pki, tmp_path):
        """_ssl._test_decode_cert is the decoder behind getpeercert(), so it is
        the oracle for the shape every reader downstream already expects."""
        decode = getattr(ssl._ssl, "_test_decode_cert", None)
        if decode is None:
            pytest.skip("this CPython build has no _test_decode_cert")
        cert = _issue(
            "example.com",
            _key(),
            issuer=pki.root,
            issuer_key=pki.root_key,
            sans=("example.com", "www.example.com"),
            org="Example Inc",
            not_before=datetime.datetime(2026, 6, 1, 0, 0, 0, tzinfo=datetime.UTC),
            not_after=datetime.datetime(2026, 9, 4, 8, 5, 9, tzinfo=datetime.UTC),
        )
        path = tmp_path / "cert.pem"
        path.write_bytes(_pem(cert))
        expected = decode(str(path))

        parsed = managers._peercert_from_der(_der(cert))
        for key in (
            "subject",
            "issuer",
            "version",
            "serialNumber",
            "notBefore",
            "notAfter",
            "subjectAltName",
        ):
            assert parsed[key] == expected[key], key
        assert parsed["notBefore"] == "Jun  1 00:00:00 2026 GMT"


# --- the real OpenSSL verifier, on loopback ----------------------------------------


@contextmanager
def tls_server(tmp_path, cert, key):
    """A TLS server on 127.0.0.1 serving `cert` alone, with no chain."""
    pem = tmp_path / "server.pem"
    pem.write_bytes(
        _pem(cert)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(pem)
    listener = socket.create_server(("127.0.0.1", 0))
    listener.settimeout(0.1)
    stop = threading.Event()

    def serve():
        while not stop.is_set():
            try:
                conn, _ = listener.accept()
            except TimeoutError:
                continue
            except OSError:
                return
            conn.settimeout(5)
            try:
                with ctx.wrap_socket(conn, server_side=True):
                    pass
            except OSError:
                pass  # the client hung up on a certificate it rejected

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1]
    finally:
        stop.set()
        thread.join(timeout=5)
        listener.close()


class TestRealHandshake:
    @pytest.mark.parametrize(
        "cert_name, trusted, reason, hostname_match",
        [
            ("valid", True, None, True),
            ("expired", False, "expired", True),
            ("wrong_host", False, "hostname_mismatch", False),
            ("chain_incomplete", False, "chain_incomplete", True),
            ("self_signed", False, "self_signed", True),
        ],
    )
    def test_openssl_reports_what_the_mocks_assume(
        self, pki, tmp_path, monkeypatch, cert_name, trusted, reason, hostname_match
    ):
        root_pem = _pem(pki.root).decode()
        real_context = ssl.create_default_context
        # Trust the test root, and only it.
        monkeypatch.setattr(
            managers.ssl,
            "create_default_context",
            lambda *a, **k: real_context(cadata=root_pem),
        )
        with tls_server(tmp_path, getattr(pki, cert_name), pki.leaf_key) as port:

            class ToTestPort(socket.socket):
                def connect(self, address):
                    assert address == ("127.0.0.1", 443)
                    super().connect(("127.0.0.1", port))

            monkeypatch.setattr(managers, "socket", SimpleNamespace(socket=ToTestPort))
            info = SSLManager.get_ssl_info(HOST, verified_ip="127.0.0.1")

        assert info["trusted"] is trusted
        assert (info["verify_error"] or {}).get("reason") == reason
        assert info["hostname_match"] is hostname_match
        assert HOST in [value for kind, value in info["subjectAltName"]] or (
            cert_name == "wrong_host"
        )
        assert info["protocol"].startswith("TLSv1.")

    def test_a_closed_port_is_unreachable(self, monkeypatch):
        listener = socket.create_server(("127.0.0.1", 0))
        port = listener.getsockname()[1]
        listener.close()  # nothing listens there now

        class ToClosedPort(socket.socket):
            def connect(self, address):
                super().connect(("127.0.0.1", port))

        monkeypatch.setattr(managers, "socket", SimpleNamespace(socket=ToClosedPort))
        info = SSLManager.get_ssl_info(HOST, verified_ip="127.0.0.1")
        assert info == {"error": "port 443 unreachable", "reason": "connection refused"}


# --- the page and the JSON API ----------------------------------------------------

BROWSER_UA = {"user-agent": "Mozilla/5.0 (Macintosh)"}
JSON_UA = {"user-agent": "curl/8.0"}
client = TestClient(app, client=("118.235.14.201", 41234))


def _gathered(ssl_data):
    return {
        "address": HOST,
        "domain": {"a": [{"ip": IP, "ttl": 300}], "mx": [], "ns": [], "txt": []},
        "location": {"country_code": "US", "country_name": "United States"},
        "whois": {"registrar": "Example Registrar"},
        "ssl": ssl_data,
        "resolved_ip": IP,
        "reverse_dns": None,
    }


def _page(ssl_data):
    with patch("main.gather", new_callable=AsyncMock, return_value=_gathered(ssl_data)):
        html = client.get(f"/{HOST}", headers=BROWSER_UA).text
    hero = html.split('class="tags"')[1].split("</div>")[0]
    section = html.split('id="acc-ssl"')[1].split("</details>")[0]
    return hero, section


class TestPage:
    def test_trusted_certificate_keeps_the_tls_valid_tag(self):
        hero, section = _page(
            {
                **VERIFIED_PEERCERT,
                "trusted": True,
                "verify_error": None,
                "hostname_match": True,
            }
        )
        assert '<span class="tag tone-success">TLS valid</span>' in hero
        assert "valid for example.com" in section

    def test_expired_certificate_renders_as_expired(self, pki):
        info, _ = _untrusted(pki.expired, 10, "certificate has expired")
        hero, section = _page(info)
        assert "TLS valid" not in hero
        assert '<span class="tag tone-danger">TLS expired</span>' in hero
        assert '<td colspan="3" class="tone-danger">expired</td>' in section
        assert "certificate has expired" in section
        assert "No certificate" not in section

    def test_hostname_mismatch_renders_as_not_valid_for_the_host(self, pki):
        info, _ = _untrusted(
            pki.wrong_host,
            62,
            "Hostname mismatch, certificate is not valid for 'example.com'.",
        )
        hero, section = _page(info)
        assert "TLS valid" not in hero
        assert "TLS hostname mismatch" in hero
        assert (
            '<td colspan="3" class="tone-danger">not valid for example.com</td>'
            in section
        )
        assert "other.example.net" in section  # the SANs it does cover

    @pytest.mark.parametrize(
        "cert_name, code, message, label",
        [
            ("self_signed", 18, "self-signed certificate", "self-signed"),
            (
                "chain_incomplete",
                20,
                "unable to get local issuer certificate",
                "chain incomplete",
            ),
        ],
    )
    def test_other_failures_name_themselves(self, pki, cert_name, code, message, label):
        info, _ = _untrusted(getattr(pki, cert_name), code, message)
        hero, section = _page(info)
        assert "TLS valid" not in hero
        assert f"TLS {label}" in hero
        assert f'<td colspan="3" class="tone-danger">{label}</td>' in section
        assert message in section

    def test_unreachable_port_is_not_no_certificate(self):
        hero, section = _page({"error": "port 443 unreachable", "reason": "timed out"})
        assert "TLS valid" not in hero
        assert "No certificate" not in section
        assert "port 443 unreachable" in section
        assert "timed out" in section

    def test_json_api_carries_the_verdict(self, pki):
        info, _ = _untrusted(pki.expired, 10, "certificate has expired")
        with patch("main.gather", new_callable=AsyncMock, return_value=_gathered(info)):
            body = client.get(f"/{HOST}", headers=JSON_UA).json()
        assert body["ssl"]["trusted"] is False
        assert body["ssl"]["hostname_match"] is True
        assert body["ssl"]["verify_error"] == {
            "code": 10,
            "message": "certificate has expired",
            "reason": "expired",
        }
        assert body["ssl"]["issuer"]  # the certificate itself is still there


# --- MCP ----------------------------------------------------------------------------

MCP_HEADERS = {
    "Content-Type": "application/json",
    "Accept": "application/json, text/event-stream",
    "Host": "ip.1kko.com",
}
INIT = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "initialize",
    "params": {
        "protocolVersion": "2026-07-28",
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "0"},
    },
}


def _call_tool(name, arguments, ssl_data, resolved_ip=IP):
    async def fake_gather(target):
        return {**_gathered(ssl_data), "resolved_ip": resolved_ip}

    main.mcp_rate_limiter.request_history.clear()
    with TestClient(app) as mcp_client:
        mcp_client.post("/mcp", json=INIT, headers=MCP_HEADERS)
        with patch("mcp_server.gather", fake_gather):
            response = mcp_client.post(
                "/mcp",
                json={
                    "jsonrpc": "2.0",
                    "id": 2,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                },
                headers=MCP_HEADERS,
            )
    return response.json()["result"]["structuredContent"]


class TestMcp:
    def test_an_untrusted_certificate_is_data_not_an_error(self, pki):
        info, _ = _untrusted(pki.expired, 10, "certificate has expired")
        payload = _call_tool("ssl_certificate", {"domain": HOST}, info)
        assert "error" not in payload
        assert payload["trusted"] is False
        assert payload["hostname_match"] is True
        assert payload["verify_error"]["reason"] == "expired"
        assert payload["verify_error"]["message"] == "certificate has expired"
        assert payload["days_remaining"] < 0
        assert payload["san"] == [HOST, f"www.{HOST}"]

    def test_a_hostname_mismatch_says_so(self, pki):
        info, _ = _untrusted(
            pki.wrong_host,
            62,
            "Hostname mismatch, certificate is not valid for 'example.com'.",
        )
        payload = _call_tool("ssl_certificate", {"domain": HOST}, info)
        assert payload["trusted"] is False
        assert payload["hostname_match"] is False
        assert payload["verify_error"]["reason"] == "hostname_mismatch"

    def test_a_trusted_certificate_says_so(self):
        info = {
            **VERIFIED_PEERCERT,
            "trusted": True,
            "verify_error": None,
            "hostname_match": True,
        }
        payload = _call_tool("ssl_certificate", {"domain": HOST}, info)
        assert payload["trusted"] is True
        assert payload["verify_error"] is None
        assert payload["issuer"] == "Let's Encrypt"

    def test_unreachable_is_an_error_naming_the_reason(self):
        payload = _call_tool(
            "ssl_certificate",
            {"domain": HOST},
            {"error": "port 443 unreachable", "reason": "connection refused"},
        )
        assert set(payload) == {"error"}
        assert "port 443 unreachable" in payload["error"]
        assert "connection refused" in payload["error"]

    def test_no_lookup_is_not_reported_as_no_certificate(self):
        payload = _call_tool(
            "ssl_certificate", {"domain": HOST}, None, resolved_ip=None
        )
        assert "No TLS certificate served" not in payload["error"]
        assert "no A record" in payload["error"]

    def test_lookup_summary_carries_the_same_distinction(self, pki):
        info, _ = _untrusted(pki.self_signed, 18, "self-signed certificate")
        tls = _call_tool("lookup", {"target": HOST}, info)["tls"]
        assert tls["trusted"] is False
        assert tls["verify_error"]["reason"] == "self_signed"

        tls = _call_tool(
            "lookup",
            {"target": HOST},
            {"error": "port 443 unreachable", "reason": "timed out"},
        )["tls"]
        assert set(tls) == {"error"}
        assert "timed out" in tls["error"]
