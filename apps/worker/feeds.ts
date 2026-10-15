import { createHash } from 'node:crypto';
import { boundedText, normalizedDomain, normalizedUrl, MAX_SOURCE_AGE, type SourceBatch } from '../../packages/intelligence/index';

export const CERT_ENDPOINT = 'https://hole.cert.pl/domains/v2/domains.txt';
export function certBatch(text: string, previous?: SourceBatch, now = Date.now()): SourceBatch {
  const firstSeen = new Map(previous?.records.map(row => [row[0], row[1]]));
  const domains = [...new Set(text.trim().split(/\r?\n/).map(line => normalizedDomain(line.trim())))].sort();
  if (domains.length < 1 || domains.length > 200000) throw new Error('CERT feed count rejected');
  return { source: 'cert-pl', retrievedAt: new Date(now).toISOString(), expiresAt: new Date(now + MAX_SOURCE_AGE).toISOString(), records: domains.map(value => [value, firstSeen.get(value) ?? new Date(now).toISOString(), createHash('sha256').update(value).digest('hex').slice(0, 24)]) };
}
// Strict CSV parser for the documented URLhaus export; comments precede the data.
export function csvRows(text: string): string[][] {
  const rows: string[][] = [];
  for (const line of text.split(/\r?\n/)) {
    if (!line.trim() || line.startsWith('#')) continue;
    const row: string[] = []; let field = '', quoted = false, closed = false;
    for (let i = 0; i < line.length; i++) {
      const c = line[i]!;
      if (c === '"') {
        if (quoted && line[i + 1] === '"') { field += '"'; i++; }
        else if (quoted) { quoted = false; closed = true; }
        else if (!field && !closed) quoted = true;
        else throw new Error('Invalid CSV quote');
      } else if (c === ',' && !quoted) { row.push(field); field = ''; closed = false; }
      else if (closed) throw new Error('Invalid CSV suffix');
      else field += c;
    }
    if (quoted) throw new Error('Truncated CSV');
    row.push(field); rows.push(row);
  }
  return rows;
}
export function urlhausBatch(text: string, now = Date.now()): { batch: SourceBatch; omitted: number } {
  const active = new Map<string, SourceBatch['records'][number]>();
  let unsupported = 0;
  for (const row of csvRows(text)) {
    if (row.length !== 9 || !/^\d+$/.test(row[0]!) || !['online', 'offline'].includes(row[3]!)) throw new Error('Unexpected URLhaus CSV format');
    if (row[3] !== 'online' || row[5] !== 'malware_download') continue;
    const date = new Date(`${row[1]!.replace(' ', 'T')}Z`);
    if (!Number.isFinite(date.getTime()) || date.getTime() > now) throw new Error('Invalid URLhaus timestamp');
    try { const value = normalizedUrl(row[2]!); active.set(value, [value, date.toISOString(), row[0]!]); }
    catch { unsupported++; }
  }
  const rows = [...active.values()].sort((a, b) => b[1].localeCompare(a[1]) || a[0].localeCompare(b[0]));
  // Chrome permits only 1,000 regex rules. Reserve headroom, expose the coverage limit.
  return { batch: { source: 'urlhaus', retrievedAt: new Date(now).toISOString(), expiresAt: new Date(now + MAX_SOURCE_AGE).toISOString(), records: rows.slice(0, 800) }, omitted: unsupported + Math.max(0, rows.length - 800) };
}
export async function download(endpoint: string, fetcher: typeof fetch = fetch): Promise<string> {
  const response = await fetcher(endpoint, { redirect: 'error', credentials: 'omit', cache: 'no-store', signal: AbortSignal.timeout(25000), headers: { accept: 'text/plain', 'user-agent': 'TwB-Intelligence/0.2' } });
  const date = response.headers.get('date');
  if (!date || !Number.isFinite(Date.parse(date)) || Math.abs(Date.now() - Date.parse(date)) > 10 * 60000) throw new Error('Source freshness could not be established');
  const modified = response.headers.get('last-modified');
  if (modified && (!Number.isFinite(Date.parse(modified)) || Date.now() - Date.parse(modified) > MAX_SOURCE_AGE)) throw new Error('Source export is stale');
  return boundedText(response, 24 * 1024 * 1024);
}
export function checkedUrlhausEndpoint(value: string): string {
  const url = new URL(value);
  if (url.origin !== 'https://urlhaus-api.abuse.ch' || !/^\/v2\/files\/exports\/[A-Za-z0-9_-]+\/(?:online|recent)\.csv$/.test(url.pathname) || url.search || url.hash || url.username || url.password) throw new Error('Use the authenticated URLhaus online.csv or recent.csv export URL from your account');
  return url.href;
}
