# TwB signed threat-feed publisher

Publisher and read-only Cloudflare delivery service for TwB Security. The browser extension and customer data are not in this repository.

CERT Polska supplies the domain warning list under its published commercial-use terms: https://cert.pl/lista-ostrzezen/. Source attribution does not imply endorsement or partnership. No malware or phishing pages are fetched.

GitHub Actions fetches the official source, validates it, signs compact full snapshots and publishes compressed data to a dedicated Cloudflare KV namespace. The edge service has no signing key. Clients independently verify signatures. Failed refreshes never extend source expiry.

Required repository secrets: TWB_SIGNING_KEY_JSON (private key material), CLOUDFLARE_API_TOKEN (dedicated account KV write permission). Required repository variables: CLOUDFLARE_ACCOUNT_ID, TWB_KV_NAMESPACE_ID. The public trust root is deploy/release.public.json. Never commit private keys or provider tokens.

The schedule is every five minutes, best effort. Free GitHub schedules may be delayed or disabled after repository inactivity; snapshots expire after 30 minutes. This is a pilot service, not an availability guarantee. Public GitHub standard runners and Workers/KV free quotas must remain available.

Use workflow_dispatch with bootstrap=true only for a genuinely empty dedicated KV namespace. Later runs recover previous signed data through the authenticated KV API even when public delivery has expired.

Review false positives before adding source/value/revokedAt/reason records to deploy/revocations.json. Source withdrawals are applied by complete snapshot replacement. Never treat community reports as confirmed evidence.

A Cloudflare cron fallback checks only KV metadata every five minutes and dispatches the fixed publication workflow when 20 minutes or less remain before expiry. Configure TWB_GITHUB_DISPATCH_TOKEN as a Worker secret with Actions read/write on this repository only, plus required metadata read. It does not need code-write permission. The deployed credential expires January 13, 2027; rotate it before that date.

Run npm ci and npm run build on Node 24. Private keys belong in Actions secrets, not public artifacts.
