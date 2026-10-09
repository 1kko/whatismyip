"""server.json for the official MCP Registry, its publish workflow, and the
page's list of MCP tools.

server.json is the entry registry.modelcontextprotocol.io lists this server
under, and directories that mirror the registry copy it from there. Once a
version is published it cannot be changed, so a wrong URL or name has to be
caught here, before anyone runs the workflow.

The page lists the MCP tools twice: in the mcp-tools meta tag an agent reads
and in the MCP note a person reads. Both used to be typed out by hand, and they
had drifted apart: the meta tag listed subdomains and the note did not. Both are
now rendered from the tools the server registered, so these tests compare the
page with what tools/list returns.

The registry schema is vendored (tests/fixtures/), so validation needs no
network. To move to a newer schema, download it from the URL that
mcp-publisher's model.CurrentSchemaURL names, save it next to the current
one, and update "$schema" in server.json.
"""

import asyncio
import json
import re
from pathlib import Path
from typing import Any
from unittest.mock import AsyncMock, patch
from urllib.parse import urlparse

import pytest
from fastapi.testclient import TestClient

import mcp_server
from config import MCP_ALLOWED_HOSTS
from main import app

SERVER_JSON = Path("server.json")
SCHEMA = Path("tests/fixtures/mcp-server.schema.2025-12-11.json")
WORKFLOW = Path(".github/workflows/mcp-publish.yml")

NAME = "io.github.1kko/whatismyip"
ENDPOINT = "https://ip.1kko.com/mcp"

BROWSER_UA = {
    "user-agent": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
        "(KHTML, like Gecko) Chrome/149.0.0.0 Safari/537.36"
    )
}
GATHERED = {
    "address": "example.com",
    "domain": {"a": [{"ip": "93.184.216.34", "ttl": 300}], "mx": [], "ns": []},
    "location": {"country_code": "US", "country_name": "United States"},
    "whois": {"registrar": "Example Registrar"},
    "ssl": None,
    "resolved_ip": "93.184.216.34",
    "reverse_dns": None,
}

client = TestClient(app, client=("118.235.14.201", 41234))


def _server() -> dict:
    return json.loads(SERVER_JSON.read_text(encoding="utf-8"))


def _workflow() -> dict:
    yaml = pytest.importorskip("yaml")
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


class TestServerJson:
    def test_names_this_server_in_the_github_namespace(self):
        # GitHub OIDC grants io.github.<repository owner>/*, and nothing else.
        assert _server()["name"] == NAME

    def test_uses_the_schema_the_registry_currently_requires(self):
        # model.CurrentSchemaURL in mcp-publisher v1.8.1. The registry flags any
        # other schema version as not current.
        server = _server()
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        assert server["$schema"] == (
            "https://static.modelcontextprotocol.io/schemas/2025-12-11/"
            "server.schema.json"
        )
        assert schema["$id"] == server["$schema"]

    def test_validates_against_the_registry_schema(self):
        jsonschema = pytest.importorskip("jsonschema")
        schema = json.loads(SCHEMA.read_text(encoding="utf-8"))
        validator = jsonschema.Draft7Validator(
            schema, format_checker=jsonschema.FormatChecker()
        )
        errors = [
            f"{'/'.join(map(str, e.absolute_path)) or '<root>'}: {e.message}"
            for e in validator.iter_errors(_server())
        ]
        assert errors == []

    def test_is_one_streamable_http_remote_at_the_public_endpoint(self):
        server = _server()
        assert server["remotes"] == [{"type": "streamable-http", "url": ENDPOINT}]
        # Remote only: a "packages" entry would make the registry go and verify
        # ownership of a package this project does not publish.
        assert "packages" not in server

    def test_remote_host_is_on_the_mcp_host_allowlist(self):
        """A host missing from MCP_ALLOWED_HOSTS gets 421 on every request.
        From a registry listing that looks like a dead server, and nothing
        in the response says why."""
        assert urlparse(_server()["remotes"][0]["url"]).hostname in MCP_ALLOWED_HOSTS

    def test_remote_url_answers_an_mcp_initialize(self):
        url = urlparse(_server()["remotes"][0]["url"])
        init = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": {
                "protocolVersion": "2026-07-28",
                "capabilities": {},
                "clientInfo": {"name": "pytest", "version": "0"},
            },
        }
        with TestClient(app) as mcp_client:
            response = mcp_client.post(
                url.path,
                json=init,
                headers={
                    "Accept": "application/json, text/event-stream",
                    "Host": url.netloc,
                },
            )
        assert response.status_code == 200
        assert response.json()["result"]["serverInfo"]["name"] == "whatismyip"

    def test_version_is_a_plain_release_semver(self):
        """The registry sorts semver and marks the highest as latest. A
        prerelease (1.2.3-1) sorts below its release, and a version that is not
        semver (2026-10-09, v1.0) is marked latest whenever it is published, so
        either would make the version history lie. See README -> MCP Registry
        for when to bump."""
        assert re.fullmatch(
            r"(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)", _server()["version"]
        )

    def test_website_and_icon_are_served_by_this_site(self):
        server = _server()
        assert server["websiteUrl"] == "https://ip.1kko.com"
        (icon,) = server["icons"]
        src = urlparse(icon["src"])
        assert (src.scheme, src.hostname) == ("https", "ip.1kko.com")
        png = Path(src.path.lstrip("/")).read_bytes()
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
        assert icon["mimeType"] == "image/png"
        width = int.from_bytes(png[16:20], "big")
        height = int.from_bytes(png[20:24], "big")
        assert icon["sizes"] == [f"{width}x{height}"]

    def test_repository_is_this_repository(self):
        repository = _server()["repository"]
        assert repository["url"] == "https://github.com/1kko/whatismyip"
        assert repository["source"] == "github"


class TestPublishWorkflow:
    def test_runs_only_when_dispatched(self):
        """A version can be published once and never changed, so publishing
        is a decision someone makes, not a side effect of a merge."""
        workflow = _workflow()
        # PyYAML reads the bare key `on` as the boolean True.
        triggers = workflow.get("on", workflow.get(True))
        assert list(triggers) == ["workflow_dispatch"]

    def test_publishes_from_a_github_hosted_runner_with_oidc_only(self):
        workflow = _workflow()
        assert workflow["permissions"] == {}
        (job,) = workflow["jobs"].values()
        # The self-hosted runner lives on the production host and runs only the
        # CI-gated deploy job.
        assert job["runs-on"] == "ubuntu-latest"
        assert job["permissions"] == {"id-token": "write", "contents": "read"}

    def test_logs_in_with_github_oidc_and_no_other_method(self):
        """`login http` makes the registry fetch /.well-known/mcp-registry-auth
        from ip.1kko.com. The suspicious-path detector bans dotfile paths for
        24 hours, so the registry would be banned and the login would fail."""
        (job,) = _workflow()["jobs"].values()
        runs = [step.get("run", "") for step in job["steps"]]
        logins = [
            line.strip()
            for run in runs
            for line in run.splitlines()
            if "mcp-publisher login" in line
        ]
        assert logins == ["./mcp-publisher login github-oidc"]

    def test_publisher_binary_is_pinned_and_checksummed(self):
        (job,) = _workflow()["jobs"].values()
        env = job["env"]
        assert re.fullmatch(r"v\d+\.\d+\.\d+", env["MCP_PUBLISHER_VERSION"])
        assert re.fullmatch(r"[0-9a-f]{64}", env["MCP_PUBLISHER_SHA256"])
        (install,) = [
            s["run"] for s in job["steps"] if "mcp-publisher.tar.gz" in s.get("run", "")
        ]
        assert "releases/latest" not in install
        assert "${MCP_PUBLISHER_VERSION}" in install
        # Checked before tar unpacks it, and before anything runs it.
        assert install.index("sha256sum --check") < install.index("tar ")

    def test_actions_are_pinned_by_full_sha(self):
        (job,) = _workflow()["jobs"].values()
        uses = [step["uses"] for step in job["steps"] if "uses" in step]
        assert uses
        for ref in uses:
            assert re.fullmatch(r"[\w./-]+@[0-9a-f]{40}", ref), ref


def _registered() -> list[str]:
    """What tools/list returns, through the SDK's public API."""
    return [tool.name for tool in asyncio.run(mcp_server.mcp.list_tools())]


def _page() -> str:
    with patch("main.gather", new_callable=AsyncMock, return_value=dict(GATHERED)):
        response = client.get("/example.com", headers=BROWSER_UA)
    assert response.status_code == 200
    return response.text


def _meta_tools(html: str) -> list[str]:
    (content,) = re.findall(r'<meta name="mcp-tools" content="([^"]*)">', html)
    return content.split(", ")


def _listed_tools(html: str) -> list[str]:
    (listed,) = re.findall(r'<span id="mcp-tool-list">([^<]*)</span>', html)
    return listed.split(", ")


class TestPageToolList:
    def test_page_lists_every_registered_tool(self):
        html = _page()
        assert _meta_tools(html) == _registered()
        assert _listed_tools(html) == _registered()
        assert "subdomains" in _registered()

    def test_a_tool_that_is_not_registered_is_not_listed(self):
        """SUBDOMAIN_ENABLED=false skips registering subdomains at import. Only
        the registration is undone here, so this checks the page follows the
        server rather than a flag of its own."""
        # patch.dict puts the registry back as it was, in its original order.
        with patch.dict(mcp_server.mcp._tool_manager._tools):
            mcp_server.mcp.remove_tool("subdomains")
            html = _page()
            registered = _registered()
        assert "subdomains" not in registered
        assert _meta_tools(html) == registered
        assert _listed_tools(html) == registered

    def test_a_newly_registered_tool_is_listed_without_a_template_change(self):
        async def probe() -> dict[str, Any]:
            return {}

        with patch.dict(mcp_server.mcp._tool_manager._tools):
            mcp_server.mcp.add_tool(probe, name="probe")
            html = _page()
        assert "probe" in _meta_tools(html)
        assert "probe" in _listed_tools(html)
