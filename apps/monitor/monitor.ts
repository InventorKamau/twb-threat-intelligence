import { z } from 'zod';
import { boundedText } from '../../packages/intelligence/index';

export const MONITOR_ORIGIN = 'https://twb-intelligence.capkamau.workers.dev';
export const MONITOR_REPOSITORY = 'InventorKamau/twb-threat-intelligence';
export type Probe = { healthy: boolean; code: 'ready' | 'unreachable' | 'invalid-health' | 'expiry-risk' | 'delivery-failed' | 'drill'; version?: number; remainingSeconds?: number };
const Health = z.strictObject({ status: z.literal('ready'), version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), expiresAt: z.iso.datetime(), sourceExpiresAt: z.iso.datetime(), indicators: z.number().int().positive().max(400000) });

export async function probeDelivery(fetcher: typeof fetch = fetch, now = Date.now()): Promise<Probe> {
  try {
    const response = await fetcher(`${MONITOR_ORIGIN}/healthz`, { redirect: 'error', credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(12000) });
    if (!response.ok) { await response.body?.cancel(); return { healthy: false, code: 'unreachable' }; }
    let health: z.infer<typeof Health>;
    try { health = Health.parse(JSON.parse(await boundedText(response, 4096))); }
    catch { return { healthy: false, code: 'invalid-health' }; }
    const remainingSeconds = Math.floor((Math.min(Date.parse(health.expiresAt), Date.parse(health.sourceExpiresAt)) - now) / 1000);
    if (remainingSeconds > 31 * 60) return { healthy: false, code: 'invalid-health' };
    if (remainingSeconds <= 5 * 60) return { healthy: false, code: 'expiry-risk', version: health.version, remainingSeconds };
    // Probe the actual update route too, without downloading the complete feed.
    const head = await fetcher(`${MONITOR_ORIGIN}/v1/update`, { method: 'HEAD', redirect: 'error', credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(12000), headers: { 'if-none-match': `"twb-${health.version}"` } });
    await head.body?.cancel();
    const etag = head.headers.get('etag') ?? '';
    if (![200, 304].includes(head.status) || !/^"twb-[1-9][0-9]{0,15}"$/.test(etag) || (head.status === 304 && etag !== `"twb-${health.version}"`) || (head.status === 200 && head.headers.get('content-encoding') !== 'gzip')) return { healthy: false, code: 'delivery-failed' };
    return { healthy: true, code: 'ready', version: health.version, remainingSeconds };
  } catch { return { healthy: false, code: 'unreachable' }; }
}

type Incident = { number: number; body: string; title: string; user: { login: string }; pull_request?: unknown };
type Api = (method: 'GET' | 'POST' | 'PATCH', path: string, body?: unknown) => Promise<unknown>;
export function githubApi(token: string, fetcher: typeof fetch = fetch): Api {
  if (!token) throw new Error('Monitor GitHub credential missing');
  return async (method, path, body) => {
    if (!/^\/issues(?:\?[a-z0-9_=&]+|\/[1-9][0-9]*(?:\/comments(?:\?[a-z0-9_=&]+)?)?)?$/.test(path)) throw new Error('Unexpected monitor API path');
    let response: Response;
    try {
      response = await fetcher(`https://api.github.com/repos/${MONITOR_REPOSITORY}${path}`, { method, redirect: 'error', signal: AbortSignal.timeout(15000), headers: { authorization: `Bearer ${token}`, accept: 'application/vnd.github+json', 'content-type': 'application/json', 'user-agent': 'TwB-Availability-Monitor', 'x-github-api-version': '2022-11-28' }, ...(body ? { body: JSON.stringify(body) } : {}) });
    } catch { throw new Error('Monitor GitHub request failed'); }
    if (!response.ok) { await response.body?.cancel(); throw new Error(`Monitor GitHub request rejected (${response.status})`); }
    return JSON.parse(await boundedText(response, 2 * 1024 * 1024)) as unknown;
  };
}

export async function monitor(options: { api: Api; probe?: () => Promise<Probe>; pause?: () => Promise<void>; mode?: 'normal' | 'drill-outage' | 'drill-recovery'; now?: () => number }): Promise<{ outcome: string; code: Probe['code']; incident?: number }> {
  const { api } = options;
  const drill = options.mode === 'drill-outage' || options.mode === 'drill-recovery';
  const marker = `<!-- twb-monitor:v1:${drill ? 'drill' : 'live'} -->`;
  const title = drill ? '[TwB drill] Availability alert test' : '[TwB] Live intelligence needs attention';
  let incident: Incident | undefined;
  // Bound pagination and only trust our bot's marked incidents, never arbitrary
  // issue instructions, titles, links or user-supplied diagnostics.
  for (let page = 1; page <= 5; page++) {
    const rows = z.array(z.object({ number: z.number().int().positive(), title: z.string(), body: z.string().nullable(), user: z.object({ login: z.string() }), pull_request: z.unknown().optional() })).parse(await api('GET', `/issues?state=open&per_page=100&page=${page}`));
    const found = rows.find(row => !row.pull_request && row.user.login === 'github-actions[bot]' && row.title === title && row.body?.startsWith(marker));
    if (found) { incident = { ...found, body: found.body! }; break; }
    if (rows.length < 100) break;
    if (page === 5) throw new Error('Monitor incident search exceeded its bound');
  }
  const probe = drill ? async (): Promise<Probe> => ({ healthy: options.mode === 'drill-recovery', code: 'drill' }) : options.probe ?? (() => probeDelivery());
  const first = await probe();
  if (first.healthy && !incident) return { outcome: 'quiet-healthy', code: first.code };
  await (options.pause ?? (() => new Promise(resolve => setTimeout(resolve, 20000))))();
  const second = await probe();
  if (first.healthy !== second.healthy) return { outcome: 'transient-no-change', code: second.code, incident: incident?.number };
  const time = new Date((options.now ?? Date.now)()).toISOString();
  if (!second.healthy) {
    if (incident) return { outcome: 'quiet-ongoing-incident', code: second.code, incident: incident.number };
    const body = `${marker}\n\n@InventorKamau ${drill ? '**Controlled alert drill. Production service is not being interrupted.**' : '**TwB intelligence delivery needs attention.**'}\n\nTwo checks 20 seconds apart reported **${second.code}** at ${time}.${second.version ? ` Last observed public version: ${second.version}.` : ''}\n\nCheck [service health](${MONITOR_ORIGIN}/healthz), [publisher runs](https://github.com/${MONITOR_REPOSITORY}/actions/workflows/publish.yml) and source expiry. Local checks continue; expired feed rules must not be extended to hide an outage.\n\nThis incident is deduplicated. Healthy confirmation will post one recovery and close it. No customer data or raw provider responses are included.`;
    const created = z.object({ number: z.number().int().positive() }).parse(await api('POST', '/issues', { title, body, assignees: ['InventorKamau'] }));
    return { outcome: 'opened', code: second.code, incident: created.number };
  }
  const recoveryMarker = '<!-- twb-monitor:recovery:v1 -->';
  const comments = z.array(z.object({ body: z.string(), user: z.object({ login: z.string() }) })).parse(await api('GET', `/issues/${incident!.number}/comments?per_page=100`));
  if (comments.length >= 100) throw new Error('Monitor recovery search exceeded its bound');
  if (!comments.some(comment => comment.user.login === 'github-actions[bot]' && comment.body.startsWith(recoveryMarker))) await api('POST', `/issues/${incident!.number}/comments`, { body: `${recoveryMarker}\n\n@InventorKamau ${drill ? 'Controlled drill recovered.' : 'TwB delivery recovered.'} Two healthy checks confirmed recovery at ${time}.${second.version ? ` Public ruleset: ${second.version}.` : ''} Routine checks return to silent operation.` });
  await api('PATCH', `/issues/${incident!.number}`, { state: 'closed', state_reason: 'completed' });
  return { outcome: 'recovered', code: second.code, incident: incident!.number };
}
