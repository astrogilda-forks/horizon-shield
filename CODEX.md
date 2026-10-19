# Use HORIZON SHIELD with OpenAI Codex

HORIZON SHIELD is a remote MCP server that audits Japanese construction and renovation estimates against fair-price data, and returns tamper-evident fair-price receipts whose SHA-256 anyone can recompute (the PTKA declaration and the dataset releases are anchored in Bitcoin, and from 2026-10-19 each day's receipts are listed in one JIDEC ledger entry the next day). It is read-only and needs no API key.

OpenAI Codex supports remote streamable HTTP MCP servers natively, so you can add HORIZON SHIELD with a single URL.

## 1. Add the server to your Codex config

Open your Codex config file at `~/.codex/config.toml` and add:

```toml
[mcp_servers.horizon-shield]
url = "https://mcp.horizonshield.dev"
```

No authentication is required. HORIZON SHIELD is a public, read-only service.

## 2. Restart Codex

Restart the Codex CLI (or reload the extension) so it picks up the new server.

## 3. Try it

Ask Codex, in natural language, for example:

```
Audit this estimate with HORIZON SHIELD: exterior wall painting, 30 tsubo, 1.5 million yen.
```

Codex calls the HORIZON SHIELD tools (get_price_range, audit_estimate, check_red_flags and others) and returns a fair-price verdict with a verifiable receipt.

## Tools exposed

audit_estimate, check_red_flags, get_price_range, get_estimate_reading_guide, get_fair_price_sources, list_cost_categories, search_cost_category, verify_fair_price, verify_integrity_claim, create_ap2_fairness_attestation, get_jccdb_dataset_info, preview_reverse_estimate, get_anonymous_estimate_review_link (formerly suggest_ehn, which still answers), get_agent_card, find_verified_contractor.

## Links

Website: https://shield.the-horizons-innovation.com
MCP endpoint: https://mcp.horizonshield.dev
