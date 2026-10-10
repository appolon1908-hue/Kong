# Kong Service Registry V1

Part of the [Kong API Gateway Control Plane V1](KONG_GATEWAY_CONTROL_PLANE_V1.md).
Machine-readable authority: `config/kong-gateway-foundation.v1.json` (`services[]`).
Validator: `python3 scripts/validate_kong_foundation.py`.

## What a service is here

A Kong service is an *approved upstream selection*. The registry does not copy
the mutable upstream URL out of the reviewed source that declares it; it binds
each service to that source (`bindings[]`, role `DESIRED` for contracts and
declarative candidates, `OBSERVED` for the sanitized production readback) and
the validator proves the source still says what the registry says. Every
service must carry:

| Field | Meaning |
| --- | --- |
| `serviceId` | stable identifier; `@staging` suffix for environment overlays |
| `owner` | accountable team for the upstream contract |
| `environment` | `development`, `staging` or `production` (never mixed) |
| `purpose` | one sentence, what the upstream does |
| `trafficClass` | `COMMAND_API`, `READ_API`, `EVENT_INGEST`, `WEBHOOK_INGEST`, `HEALTH`, `ADMIN`, `IDENTITY`, `PUBLIC_FORM`, `PUBLIC_PROBE`, `TENANT_PRODUCT_API`, `EDITOR_UI`, `STANDBY_REHEARSAL`, `LEGACY_SHARED_KEY`, `TEST` |
| `upstreamClass` | who the upstream is architecturally (see below) |
| `upstream` | `{protocol, host, port}` desired target; cross-checked against every binding |
| `healthProfile` | how upstream health is determined (`profiles.health`) |
| `timeoutProfile` / `retryProfile` | transport policy ([timeout profiles](timeout-profiles-v1.md), [retry policy](retry-policy-v1.md)) |
| `authenticationProfile` | the gateway authentication class its routes require |
| `authorizationPrerequisiteProfile` | which gateway prerequisites (audience, scope, tenant, authorized party, realm role) are enforced before Middleware decides |
| `rateLimitProfile` / `requestSizeProfile` | service-level profile or `ROUTE_SPECIFIC` |
| `observabilityProfile` | metrics/correlation posture |
| `lifecycle` / `disposition` | `CANONICAL`, `TRANSITIONAL`, `LEGACY`, `STANDBY`, `RETIRE_CANDIDATE`, `PREPARED_DISABLED`, `PROPOSED`, `DESIGN_ONLY` × `KEEP`, `REFACTOR`, `MOVE`, `DEPRECATE`, `DELETE` |
| `acceptedFindings` | the exact debt findings the validator detects on it; a mismatch either way fails |

An unowned, unclassified or unbound service is not deployable: the validator
rejects the registry.

## Upstream classes and the Middleware boundary

| Upstream class | Meaning | Allowed on canonical? |
| --- | --- | --- |
| `MIDDLEWARE_GOVERNED` | Middleware public API; command/business authorization happens there | yes; target must be a declared alias |
| `CONTROL_PLANE_GOVERNED` | the communication control plane family (`:8096`) | yes |
| `MIDDLEWARE_EVENT_GATEWAY` | legacy Middleware event gateway container | legacy only |
| `APPLICATION_DIRECT` | an application reached without Middleware (n8n editor UI, MoneyBee API, mail API, marketing fragment) | only with `directUpstreamReason` |
| `LEGACY_AUTH_ADAPTER` / `LEGACY_PROVIDER_ADAPTER` | shared-key adapters (`codestra-kong-service-auth-adapter-1`, `codestra-email-reseller-api-1`, `codestra-sms-api-api-1`) | never; `LEGACY_UPSTREAM` finding |
| `STANDBY_AUTH_FIXTURE` | private standby auth middleware in front of a no-delivery fixture | standby only |
| `CERTIFICATION_TOOLING` | identity-certification probe | transitional only |
| `TEST` | `kong-test-upstream` | never; `TEST_UPSTREAM` finding |
| `DESIGN_LOGICAL` | logical upstream families of the cell design | design only |

Every Middleware-governed service must target one of the declared aliases in
`boundaryRules.middlewareUpstreamAliases`. PR #105 consolidated the shared edge
on the 8095 listener; the readback of 2026-09-06 still shows the 8080/8095/8096
split, which the registry records as declared drift and retired residue:

| Alias | Role | Disposition |
| --- | --- | --- |
| `middleware-integration-api:8095` | **canonical public API** (PR #105): the v2 authority, both generated manifests, the campaign contract and the retired n8n contract bind it | keep; every Middleware authority targets it |
| `codestra-middleware-integration-api-1:8095` | container name of the same listener (callbacks, intake, calling, PR #104 read contract, website API, breero fail-closed target) | keep; same listener |
| `appolon-middleware-integration-api:8080` | **retired and denied** (`RETIRED_DENIED_PR105`); `RETIRED_UPSTREAM_ALIAS` is detected on anything that targets it | no activatable route: live n8n residue is `RETIRE_CANDIDATE` with `knownDrift`, the prepared provider-control contract pins 8095 (activation still waits on the PR 82/60 identities) |
| `codestra-integration-control-plane-api-1:8096` / `codestra-control-plane:8096` | communication control plane (legacy key-auth alias / canonical OIDC alias) | the OIDC candidate supersedes the key-auth routes |
| `codestra-middleware-event-gateway-1:8095` | legacy webhook event gateway | deprecate with the shared-key routes |
| `${MIDDLEWARE_TLS_HOST}:443` | proposed TLS egress | proposal; not activatable until a gateway authentication plugin is added |
| `middleware.internal.codestra:443` | gateway-platform design (integration examples) | design |

Provider upstreams (Twilio, SendGrid, Telnexa, scraper, VICIdial, …) and IP
literals are never valid service targets: the validator blocks any route that
reaches one (`DIRECT_PROVIDER_UPSTREAM`, `HARD_CODED_UPSTREAM_IP`). The two
routes that had them in the 2026-09-06 readback (`breero-production-api-route`
→ `scraper.internal.codestra.agency:8443`, `codestra-website-api-route` →
`10.40.0.3:8443`) are already fail-closed to Middleware in the inventory
candidate and remain `TRANSITIONAL`.

## Upstream health and load balancing

No reviewed source declares a Kong `upstream` object; every service targets one
DNS name. That is the `DNS_TARGET_PASSIVE` health profile: DNS failure,
connection refusal, timeout and upstream 5xx surface as the route's own
502/503/504 and never select an older service or a provider. Because there is a
single target per service, there is no load-balancing algorithm to document
yet; the moment a second target is introduced the service must move to
`ACTIVE_HTTP_REQUIRED` (Kong upstream object, active HTTP checks on a literal
health path, documented algorithm, target ownership and environment) before
activation. An open TCP port is not treated as a healthy Middleware.

## Environment separation

Services are registered per environment. Staging overlays (`@staging`) bind
only the staging overlay contract, which the validator proves uses the staging
issuer, declares a subset of the production routes with identical matches, and
records `sharedUpstreamAliases: true` because the overlays reuse the production
aliases (`middleware-integration-api:8095`, and the retired
`appolon-middleware-integration-api:8080` only in the retired n8n overlay).
Those aliases are safe only because
the staging node runs in a dedicated stack with its own networks, Redis and
database; that isolation is a deployment invariant, not a naming one, and it is
listed as runtime certification evidence in the freeze document. Development
has no checked-in source: local nodes validate rendered documents with decK and
never bind the staging or production issuer.

## Registry

Generated from the registry and the bound sources by
`scripts/validate_kong_foundation.py --write-docs`; CI fails if it is stale.

<!-- BEGIN GENERATED: services -->
| Service | Env | Owner | Repository | Class | Upstream | TLS | Route families | Timeout | Retry | Auth | Rate | Size | Health | Lifecycle | Disposition | Findings |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| `breero-production-api` | production | unassigned | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | `/api/v1`, `/health` | LEGACY_CONNECT_5S | UNRECORDED_READBACK | AUTHENTICATED | UNRECORDED_READBACK | UNRECORDED_READBACK | DNS_TARGET_PASSIVE | TRANSITIONAL | REFACTOR | RETRIES_UNRECORDED |
| `codestra-callback-api` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | `/api/v1/callbacks`, `/api/v1/control` | FAST_SERVICE_API | TRANSPORT_CONNECT_ONLY_1 | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-calling-api` | production | middleware-telephony | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | `/api/v1/realtime`, `/v1/telephony/commands`, `/v1/telephony/operations` | STANDARD_API | NONE | INTERNAL | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-campaign-automation-api` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | `/api/v1/automation`, `/api/v1/integrations` | STANDARD_API | NONE | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-communication-control-plane` | production | platform-control-plane | appolon1908/Middleware- | CONTROL_PLANE_GOVERNED | `http://codestra-integration-control-plane-api-1:8096` | private network | `/api/v1/control`, `/api/v1/messages`, `/api/v1/results` | KONG_DEFAULT_60S | UNRECORDED_READBACK | AUTHENTICATED | UNRECORDED_READBACK | UNRECORDED_READBACK | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-community-n8n-middleware` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `https://${MIDDLEWARE_TLS_HOST}:443` | required | `/v1/integrations/n8n` | STANDARD_API | NONE | SERVICE_AUTHENTICATED | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | DNS_TARGET_PASSIVE | RETIRE_CANDIDATE | DELETE | RETRIES_UNDECLARED, TIMEOUTS_UNDECLARED |
| `codestra-control-plane` | production | platform-control-plane | appolon1908/Middleware- | CONTROL_PLANE_GOVERNED | `http://codestra-control-plane:8096` | private network | 7 families | STANDARD_API | NONE | SERVICE_AUTHENTICATED | AUTHENTICATED_STANDARD_120 | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-crm-api` | production | legacy-shared-key-consumers | UNATTRIBUTED | LEGACY_AUTH_ADAPTER | `http://codestra-kong-service-auth-adapter-1:8080` (DELETE) | private network | `/v1/crm` | LEGACY_FAST_5S | UNRECORDED_READBACK | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | RETRIES_UNRECORDED |
| `codestra-design-cell-upstreams` | production | architecture | appolon1908/Middleware- | DESIGN_LOGICAL | `None://middleware-*:None` | private network | 15 families | STANDARD_API | NONE | SERVICE_AUTHENTICATED | DESIGN_UNSPECIFIED | DESIGN_UNSPECIFIED | DNS_TARGET_PASSIVE | DESIGN_ONLY | KEEP | RETRIES_UNDECLARED, TIMEOUTS_UNDECLARED |
| `codestra-email-api` | production | legacy-shared-key-consumers | UNATTRIBUTED | LEGACY_PROVIDER_ADAPTER | `http://codestra-email-reseller-api-1:8080` (DELETE) | private network | `/v1/email` | KONG_DEFAULT_60S | UNRECORDED_READBACK | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-email-standby` | production | gateway-standby | appolon1908/Kong | STANDBY_AUTH_FIXTURE | `http://codestra-kong-standby-auth:8080` (TEST_ONLY) | private network | `/v1/email` | STANDBY_FAST | NONE | INTERNAL | ROUTE_SPECIFIC | ROUTE_SPECIFIC | NONE_FIXTURE | STANDBY | KEEP | — |
| `codestra-email-webhook-standby` | production | gateway-standby | appolon1908/Kong | STANDBY_AUTH_FIXTURE | `http://codestra-kong-standby-auth:8080` (TEST_ONLY) | private network | `/v1/webhooks/email` | STANDBY_FAST | NONE | INTERNAL | ROUTE_SPECIFIC | ROUTE_SPECIFIC | NONE_FIXTURE | STANDBY | KEEP | — |
| `codestra-gateway-test` | production | unassigned | UNATTRIBUTED | TEST | `http://kong-test-upstream:8080` (DELETE) | private network | `/v1/test` | KONG_DEFAULT_60S | UNRECORDED_READBACK | AUTHENTICATED | NONE | NONE_READ_ONLY | NONE_FIXTURE | RETIRE_CANDIDATE | DELETE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-mail-control-plane` | production | unassigned | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-mail-api:8098` | private network | `/api/v1/admin`, `/api/v1/mail` | LEGACY_CONNECT_5S | UNRECORDED_READBACK | ADMIN_INTERNAL | NONE | UNBOUNDED | DNS_TARGET_PASSIVE | TRANSITIONAL | REFACTOR | RETRIES_UNRECORDED |
| `codestra-middleware-intake` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | `/v1/intake/leads`, `/v1/intake/surveys` | STANDARD_API | NONE | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-middleware-n8n-control-plane` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | `/v1/integrations/n8n` | FAST_SERVICE_API | TRANSPORT_CONNECT_ONLY_1 | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | RETIRE_CANDIDATE | DELETE | — |
| `codestra-n8n-editor` | production | automation-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-n8n-main:5678` | private network | `/` | LONG_RUNNING_API | NONE | AUTHENTICATED | ROUTE_SPECIFIC | EDITOR_4MB | DNS_TARGET_PASSIVE | PROPOSED | KEEP | — |
| `codestra-platform-api` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | 10 families | STANDARD_API | KONG_DEFAULT_IMPLICIT | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | TRANSITIONAL | REFACTOR | IMPLICIT_RETRIES |
| `codestra-sms-api` | production | legacy-shared-key-consumers | UNATTRIBUTED | LEGACY_AUTH_ADAPTER | `http://codestra-kong-service-auth-adapter-1:8080` (DELETE) | private network | `/v1/sms` | FAST_SERVICE_API | UNRECORDED_READBACK | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | RETRIES_UNRECORDED |
| `codestra-sms-dlr` | production | legacy-shared-key-consumers | UNATTRIBUTED | LEGACY_PROVIDER_ADAPTER | `http://codestra-sms-api-api-1:8080` (DELETE) | private network | `/v1/sms/dlr` | KONG_DEFAULT_60S | UNRECORDED_READBACK | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-sms-standby` | production | gateway-standby | appolon1908/Kong | STANDBY_AUTH_FIXTURE | `http://codestra-kong-standby-auth:8080` (TEST_ONLY) | private network | `/v1/sms` | STANDBY_FAST | NONE | INTERNAL | ROUTE_SPECIFIC | ROUTE_SPECIFIC | NONE_FIXTURE | STANDBY | KEEP | — |
| `codestra-sms-webhook-standby` | production | gateway-standby | appolon1908/Kong | STANDBY_AUTH_FIXTURE | `http://codestra-kong-standby-auth:8080` (TEST_ONLY) | private network | `/v1/webhooks/sms` | STANDBY_FAST | NONE | INTERNAL | ROUTE_SPECIFIC | ROUTE_SPECIFIC | NONE_FIXTURE | STANDBY | KEEP | — |
| `codestra-token-validator` | production | identity-certification | UNATTRIBUTED | CERTIFICATION_TOOLING | `http://identity-certification:8080` (TEST_ONLY) | private network | `/v1/identity-token-certification` | KONG_DEFAULT_60S | UNRECORDED_READBACK | PUBLIC | UNRECORDED_READBACK | NONE_READ_ONLY | DNS_TARGET_PASSIVE | TRANSITIONAL | DEPRECATE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-webhooks` | production | legacy-shared-key-consumers | appolon1908/Middleware- | MIDDLEWARE_EVENT_GATEWAY | `http://codestra-middleware-event-gateway-1:8095` | private network | `/v1/webhooks` | KONG_DEFAULT_60S | UNRECORDED_READBACK | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | LEGACY | DEPRECATE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `codestra-website-api` | production | website | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://codestra-middleware-integration-api-1:8095` | private network | `/api/v1/analytics`, `/api/v1/contact-requests`, `/api/v1/demo-requests`, `/api/v1/localization`, `/api/v1/pricing-requests` | FAST_SERVICE_API | UNRECORDED_READBACK | PUBLIC | NONE | UNBOUNDED | DNS_TARGET_PASSIVE | TRANSITIONAL | REFACTOR | RETRIES_UNRECORDED |
| `codestra-website-forms` | production | website | appolon1908/Middleware- | CONTROL_PLANE_GOVERNED | `http://codestra-integration-control-plane-api-1:8096` | private network | `/v1/forms/demo-request`, `/v1/forms/electronic-billing-application`, `/v1/forms/electronic-billing-registration`, `/v1/forms/pricing-request`, `/v1/forms/sales-contact` | KONG_DEFAULT_60S | UNRECORDED_READBACK | PUBLIC | UNRECORDED_READBACK | UNBOUNDED | DNS_TARGET_PASSIVE | LEGACY | MOVE | KONG_DEFAULT_TIMEOUTS, RETRIES_UNRECORDED |
| `middleware-integration-api` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | 42 families | CANONICAL_EDGE_5S | NONE | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `moneybee-api` | production | moneybee-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://moneybee-api:8000` | private network | `/api/v2/account` | STANDARD_API | NONE | AUTHENTICATED | ROUTE_SPECIFIC | IDENTITY_BOOTSTRAP_64KB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `provider-control-middleware` | production | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | `/api/v1/control`, `/api/v1/odoo` | STANDARD_API | NONE | SERVICE_AUTHENTICATED | UNSPECIFIED_CONTRACT | UNSPECIFIED_CONTRACT | DNS_TARGET_PASSIVE | PREPARED_DISABLED | KEEP | RETRIES_UNDECLARED, TIMEOUTS_UNDECLARED |
| `codestra-ai` | staging | marketing-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-ai:8000` | private network | `/v1/ai` | KONG_DEFAULT_IMPLICIT | KONG_DEFAULT_IMPLICIT | AUTHENTICATED | NONE | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | DESIGN_ONLY | REFACTOR | IMPLICIT_RETRIES, IMPLICIT_TIMEOUTS |
| `codestra-campaign-automation-api@staging` | staging | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | `/api/v1/integrations` | STANDARD_API | NONE | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `codestra-communication` | staging | marketing-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-communication:8000` | private network | `/v1/communications` | KONG_DEFAULT_IMPLICIT | KONG_DEFAULT_IMPLICIT | AUTHENTICATED | NONE | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | DESIGN_ONLY | REFACTOR | IMPLICIT_RETRIES, IMPLICIT_TIMEOUTS |
| `codestra-marketing` | staging | marketing-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-marketing:8000` | private network | `/v1/marketing` | KONG_DEFAULT_IMPLICIT | KONG_DEFAULT_IMPLICIT | AUTHENTICATED | NONE | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | DESIGN_ONLY | REFACTOR | IMPLICIT_RETRIES, IMPLICIT_TIMEOUTS |
| `codestra-middleware-n8n-control-plane@staging` | staging | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | `/v1/integrations/n8n` | FAST_SERVICE_API | TRANSPORT_CONNECT_ONLY_1 | SERVICE_AUTHENTICATED | ROUTE_SPECIFIC | STANDARD_API_1MB | DNS_TARGET_PASSIVE | RETIRE_CANDIDATE | DELETE | — |
| `codestra-social` | staging | marketing-platform | UNATTRIBUTED | APPLICATION_DIRECT | `http://codestra-social:8000` | private network | `/v1/social` | KONG_DEFAULT_IMPLICIT | KONG_DEFAULT_IMPLICIT | AUTHENTICATED | NONE | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | DESIGN_ONLY | REFACTOR | IMPLICIT_RETRIES, IMPLICIT_TIMEOUTS |
| `middleware-integration-api@staging` | staging | middleware-integration | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `http://middleware-integration-api:8095` | private network | 42 families | CANONICAL_EDGE_5S | NONE | AUTHENTICATED | ROUTE_SPECIFIC | ROUTE_SPECIFIC | DNS_TARGET_PASSIVE | CANONICAL | KEEP | — |
| `moneybee-bootstrap` | staging | moneybee-platform | appolon1908/Middleware- | MIDDLEWARE_GOVERNED | `https://middleware.internal.codestra:443` | required | `/api/v2/account` | FAST_SERVICE_API | NONE | AUTHENTICATED | ROUTE_SPECIFIC | IDENTITY_BOOTSTRAP_64KB | ACTIVE_HTTP_REQUIRED | DESIGN_ONLY | KEEP | — |
<!-- END GENERATED: services -->

Runtime drift between the desired contracts and the 2026-09-06 readback is
listed in the [route registry](route-registry-v1.md#declared-runtime-drift).
