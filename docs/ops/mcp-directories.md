# MCP directory listings

Where the MCP endpoint (`https://ip.1kko.com/mcp`) is listed, and what each
listing needs. Every step here is manual and done by the owner. Nothing in the
repository submits anything on its own.

On 2026-10-09, a search for `1kko` on the official registry returned 0 servers
(`GET https://registry.modelcontextprotocol.io/v0/servers?search=1kko`), and
Glama returned nothing for `1kko` or `whatismyip`.

## Before submitting anywhere: `/.well-known` gets banned

Several directories verify ownership, or probe for metadata, at a path under
`https://ip.1kko.com/.well-known/`. The suspicious-path detector matches it
(`/\..*`, and `\.json$` for `.json` files), so that request gets a `403` and
the requesting IP is banned for 24 hours (`BAN_DURATION_SUSPICIOUS`).

- The ban never reaches `/mcp`: only a manual ban applies there. A directory's
  scan or health check over MCP keeps working.
- The ban does cover every other path, `/static` included. A crawler banned
  this way cannot fetch the icon (`/static/image/logo.png`) or the website
  preview. If a listing shows no icon, look for its IP in `GET /admin/bans`
  and unban it with `DELETE /admin/ban/{ip}`.
- So pick DNS or GitHub verification over HTTP-file verification wherever a
  directory offers both. Settled decision 2 allows an exemption only for an
  exact path, and none exists for `/.well-known/*`.

## 1. Official MCP Registry: do this first

PulseMCP and Glama both read from the registry, so this one listing may be
enough to appear in both.

| Needs | Where it is |
|---|---|
| `server.json` (name `io.github.1kko/whatismyip`, one `streamable-http` remote) | repository root |
| Namespace proof: GitHub OIDC, which grants `io.github.1kko/*` | `.github/workflows/mcp-publish.yml` |
| A version not published before | `version` in `server.json`; see README → MCP Registry |

- [ ] Merge, then wait for the Deploy workflow to finish.
- [ ] Actions → **Publish to MCP Registry** → Run workflow, on `main`.
- [ ] Confirm it is listed:
      `curl -s 'https://registry.modelcontextprotocol.io/v0/servers?search=io.github.1kko/whatismyip'`

Do not use `mcp-publisher login http`. It makes the registry fetch
`/.well-known/mcp-registry-auth`, which bans the registry (see above) and
fails the login.

## 2. PulseMCP

| Needs | Status |
|---|---|
| A listing in the official registry | from step 1 |
| A web form submission | paused: "submissions and changes are temporarily paused" (pulsemcp.com/submit, last updated 2026-09-03) |

The submit page says a server published to the official registry is "the best
first step even when we are not paused, and we will pick it up automatically
once we are back."

- [ ] A few days after step 1, search pulsemcp.com/servers for `whatismyip`.
- [ ] If it is still missing once submissions reopen, submit it at
      pulsemcp.com/submit.

## 3. Glama

| Needs | Notes |
|---|---|
| A listing as a "connector" | Glama names remote servers by their registry name (`glama.ai/mcp/connectors/io.github.<owner>/<name>`), so step 1 should create it |
| A Glama account, to claim the listing | a claim lets you edit the description and see usage and health |
| Ownership proof | DNS TXT record, an HTTP file, or for an `io.github.*` name possibly the matching GitHub account |

- [ ] A few days after step 1, open
      `https://glama.ai/mcp/connectors/io.github.1kko/whatismyip`. If it is
      not there, sign in and add the connector with the URL
      `https://ip.1kko.com/mcp`.
- [ ] Claim it with the **DNS challenge**: publish the TXT record Glama shows
      (`_glama-claim.ip.1kko.com`, token prefix `glama_claim_`). Keep the
      record, because Glama re-checks it and removes the claim 7 days after
      the record disappears.
- [ ] Do **not** use the HTTP challenge. `/.well-known/glama.json` gets
      Glama's checker banned (see above), and the claim fails.
- [ ] No test profile is needed. The endpoint needs no authentication, so the
      health check can connect without one.

## 4. Smithery

| Needs | Notes |
|---|---|
| A Smithery account (GitHub sign-in) | the listing lives under a Smithery namespace, e.g. `@1kko/whatismyip` |
| A public HTTPS URL that speaks Streamable HTTP | `https://ip.1kko.com/mcp` |
| OAuth only if the server requires auth | it does not |
| A server card at `/.well-known/mcp/server-card.json` | optional; Smithery reads it only when its scan cannot finish, and that path would need a detector exemption |

- [ ] smithery.ai/new → enter `https://ip.1kko.com/mcp` → finish the flow.
      (Or with the CLI: `smithery mcp publish "https://ip.1kko.com/mcp" -n @1kko/whatismyip`.)
- [ ] Confirm the scan lists all of the tools. If it fails with a `403`, find
      the scanner's request in the logs (user-agent `SmitheryBot/1.0`). A
      `403 Invalid Origin header` means it sends an `Origin` that is not in
      `MCP_ALLOWED_ORIGINS`, so add that origin. Any other `403` on `/mcp` is a
      manual ban. A wrong `Host` would get a `421`, not a `403`.
- [ ] Optionally, work through Settings → Verification on the server page.
