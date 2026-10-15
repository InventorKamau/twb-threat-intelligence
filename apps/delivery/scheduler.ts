import type { DeliveryEnv } from './worker';

const dispatch = 'https://api.github.com/repos/InventorKamau/twb-threat-intelligence/actions/workflows/publish.yml/dispatches';

// Small fallback only: feed parsing and signing stay on the hosted runner.
// The dedicated GitHub token has Actions write on this one repository, no code
// write or secrets-read permission, and is never available to HTTP clients.
export async function refreshAgingPublication(env: DeliveryEnv, fetcher: typeof fetch = fetch, now = Date.now()): Promise<'fresh' | 'dispatched'> {
  const { value, metadata } = await env.TWB_RULESETS.getWithMetadata('current', { type: 'stream', cacheTtl: 60 });
  await value?.cancel();
  if (value && metadata && Date.parse(metadata.expiresAt) - now > 20 * 60000) return 'fresh';
  if (!env.TWB_GITHUB_DISPATCH_TOKEN) throw new Error('Publisher fallback credential is not configured');
  let response: Response;
  try {
    response = await fetcher(dispatch, {
      method: 'POST', redirect: 'error', signal: AbortSignal.timeout(20000),
      headers: { authorization: `Bearer ${env.TWB_GITHUB_DISPATCH_TOKEN}`, accept: 'application/vnd.github+json', 'content-type': 'application/json', 'user-agent': 'TwB-Intelligence-Scheduler', 'x-github-api-version': '2022-11-28' },
      body: JSON.stringify({ ref: 'main', inputs: { bootstrap: false } }),
    });
  } catch { throw new Error('Publisher fallback request failed'); }
  await response.body?.cancel();
  if (response.status !== 204) throw new Error('Publisher fallback was rejected');
  return 'dispatched';
}
