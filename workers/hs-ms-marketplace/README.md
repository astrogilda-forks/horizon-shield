# hs-ms-marketplace

The Microsoft Marketplace side of HORIZON SHIELD's SaaS offer: the landing page a buyer is sent to after purchase, and
the connection webhook Microsoft calls for subscription events. Deployed at `https://marketplace.horizonshield.dev`.

| Route | What it does |
|---|---|
| `GET /landing?token=...` | Keeps the purchase token server side and sends the buyer to Microsoft sign-in (Entra ID or a personal Microsoft account, `id_token` by `form_post`). |
| `POST /auth/callback` | Verifies the `id_token` (RS256 against Microsoft's keys, audience, issuer bound to the token's tenant, nonce), resolves the purchase with the SaaS Fulfillment API and shows what was bought. Nothing is billed yet. |
| `POST /activate` | The buyer pressed Activate: calls the Activate API (billing starts only on success) and records the subscription. Single use. |
| `POST /webhook` | Verifies Microsoft's Entra bearer token (signature, issuer, `tid`, `aud` = the API app, caller `appid`/`azp` = the Marketplace API), then confirms the event with the Get Operation API before recording it. ChangePlan and ChangeQuantity are accepted by not sending a PATCH. |
| `GET /admin/subscriptions` | The recorded subscriptions and their events, for the operator (bearer `ADMIN_TOKEN`). |
| `GET /health` | Version and whether the worker is configured (never the values). |

Partner Center, offer technical configuration:

- Landing page URL: `https://marketplace.horizonshield.dev/landing`
- Connection webhook: `https://marketplace.horizonshield.dev/webhook`
- Microsoft Entra tenant ID: the tenant that holds the API app
- Microsoft Entra application ID: the API app (single tenant)

Two Entra apps, as Microsoft's registration guide asks: a single-tenant app with a client secret that calls the
fulfillment APIs (its service principal must sit in the same tenant as the Marketplace API's,
`20e940b3-4c77-4b0b-9a53-9e16a1b010a7`), and a separate sign-in app for buyers from any organisation or a personal
Microsoft account, with no secret (ID tokens only).

Tests: `node test/worker.test.mjs` (offline; Microsoft's endpoints are faked and every request is checked).

What this worker does not do: deliver the service. An activated subscription is recorded and the operator starts the
engagement; the buyer is told so on the page.
