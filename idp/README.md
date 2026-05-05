# IdP Verification Stacks

This directory ships `docker compose` definitions for self-hosted OIDC
providers used to verify the **Custom1..Custom8** generic slots in
`oauth2_passkey`. It is the operator quick-reference for bringing the
stacks up and down. Detailed setup walkthroughs (registering an
application, wiring env vars, troubleshooting) live in
[../docs/src/guides/generic-oidc.md](../docs/src/guides/generic-oidc.md).

| Stack        | Directory          | Issuer URL                              | Admin / UI                                    |
|--------------|--------------------|-----------------------------------------|-----------------------------------------------|
| Zitadel v2   | `idp/zitadel/`     | `http://localhost:8080`                 | Console at `http://localhost:8080/ui/console` |
| Zitadel v4   | `idp/zitadel-v4/`  | `http://localhost:8080`                 | Console at `http://localhost:8080/ui/console` |
| Ory Hydra    | `idp/ory-hydra/`   | `http://localhost:4444`                 | Admin API at `http://localhost:4445`          |
| Authentik    | `idp/authentik/`   | `http://localhost:9000/application/o/{slug}/` | Admin UI at `http://localhost:9000`     |
| Keycloak     | `idp/keycloak/`    | `http://localhost:8180/realms/{realm}`  | Admin console at `http://localhost:8180`      |

`idp/zitadel/` (v2.71.x, embedded V1 login) and `idp/zitadel-v4/` (v4.x,
separate `zitadel-login` Next.js service) both bind to `:8080` and are
mutually exclusive — bring one down before bringing the other up. v4 is
the official upstream compose and is closer to what cloud-hosted Zitadel
runs today; v2 is kept because its single-container setup is simpler and
it supports `response_mode=form_post` natively.

Ports are bound to `127.0.0.1` only. Named Docker volumes persist state
so you can `down` and bring the stack back up without losing data.

---

## Prerequisites

- Docker Engine 20.10+ with Compose v2
- One of the demo apps in this repo running (e.g. `demo-both`)
- `ORIGIN` set to a URL reachable by your browser — typically
  `http://localhost:3001` for the demos

Redirect URI format for every Custom slot is:

```
{ORIGIN}/o2p/oauth2/{OAUTH2_CUSTOM{N}_NAME}/authorized
```

e.g. with `ORIGIN=http://localhost:3001` and `OAUTH2_CUSTOM1_NAME=zitadel`:

```
http://localhost:3001/o2p/oauth2/zitadel/authorized
```

---

## Zitadel v2

```bash
cd idp/zitadel
docker compose up -d
docker compose logs -f zitadel   # wait for "server is listening on [::]:8080"

# Default IAM Owner credentials (printed during init):
docker compose logs zitadel | grep -A2 "IAM Owner"

# Tear down (preserve volumes / wipe everything):
docker compose down
docker compose down -v
```

> **Why v2.71.x and not `latest`?** Zitadel v3+ redirects `/ui/console`
> to the separate `zitadel-login` Next.js service, which is not bundled
> with the main container. v2.71.x still ships the embedded V1 login UI
> and works standalone — which is what this stack needs. Use the v4
> stack below if you want to test the multi-service setup.

Setup walkthrough: [Zitadel (Self-Hosted)](../docs/src/guides/generic-oidc.md#zitadel-self-hosted).

---

## Zitadel v4

```bash
cd idp/zitadel-v4
docker compose up -d
docker compose logs -f zitadel

docker compose down
docker compose down -v
```

v4 splits Zitadel and the login UI into separate services. It silently
downgrades `response_mode=form_post` to `query`, so set
`OAUTH2_CUSTOM{N}_RESPONSE_MODE=query` in your `.env`.

Setup walkthrough: [Zitadel (Self-Hosted)](../docs/src/guides/generic-oidc.md#zitadel-self-hosted)
(same registration flow as v2; the response-mode caveat is in
[Troubleshooting](../docs/src/guides/generic-oidc.md#zitadel-returns-invalid-response-mode-get-is-not-allowed-for-form_post)).

---

## Ory Hydra

```bash
cd idp/ory-hydra
docker compose up -d
docker compose logs -f hydra

# Verify Hydra is up:
curl -s http://localhost:4444/.well-known/openid-configuration | jq .issuer
# -> "http://localhost:4444"

docker compose down
docker compose down -v       # wipes Postgres volume
```

Hydra has no admin UI — clients are registered via `docker compose exec`.
The bundled consent container runs with `CONFORMITY_FAKE_CLAIMS=1` so
sign-in works out of the box for testing. Hydra also requires
`OAUTH2_CUSTOM{N}_RESPONSE_MODE=query`.

Setup walkthrough: [Ory Hydra (Self-Hosted)](../docs/src/guides/generic-oidc.md#ory-hydra-self-hosted).

---

## Authentik

```bash
cd idp/authentik
cp .env.example .env

# Generate AUTHENTIK_SECRET_KEY and set AUTHENTIK_BOOTSTRAP_PASSWORD:
openssl rand -base64 60 | tr -d '\n'
$EDITOR .env

docker compose up -d
docker compose logs -f server   # wait for "Starting main process"

# Health check:
curl -s -o /dev/null -w '%{http_code}\n' http://localhost:9000/-/health/live/
# -> 204

docker compose down
docker compose down -v       # wipes Postgres + Redis volumes
```

The `openssl rand` step **must** happen before `docker compose up` —
Authentik refuses to start without `AUTHENTIK_SECRET_KEY` set in `.env`.

Setup walkthrough: [Authentik (Self-Hosted)](../docs/src/guides/generic-oidc.md#authentik-self-hosted).

---

## Keycloak

```bash
cd idp/keycloak
docker compose up -d
docker compose logs -f keycloak

docker compose down
docker compose down -v
```

Setup walkthrough:
[Keycloak Provider Setup](../docs/src/guides/keycloak.md).

---

## JWKS cache reset (after switching IdP versions)

If you switch between Zitadel v2 and v4 (both bind to `:8080`), the
oauth2-passkey JWKS cache holds the previous instance's keys for up to
10 minutes. Flush just the stale entry:

```bash
docker exec <redis-container> redis-cli \
    DEL 'cache:jwks:http://localhost:8080/oauth/v2/keys'
```

Use `FLUSHDB` if you don't mind wiping the entire cache. In-memory
caches clear on demo-app restart.

See
[JWKS stale after switching IdP versions on the same host](../docs/src/guides/generic-oidc.md#jwks-stale-after-switching-idp-versions-on-the-same-host)
for the full explanation.
