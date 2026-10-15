import { z } from 'zod';
import { parse } from 'tldts';

export const MAX_UPDATE_BYTES = 48 * 1024 * 1024;
export const MAX_SOURCE_AGE = 30 * 60000;
export const Source = z.enum(['cert-pl', 'urlhaus']);
const timestamp = z.iso.datetime();
export const IndicatorSchema = z.strictObject({
  type: z.enum(['domain', 'url']), value: z.string().min(1).max(1800),
  classification: z.enum(['phishing', 'malware', 'unknown']), status: z.enum(['observed', 'suspicious', 'confirmed', 'revoked']),
  source: Source, evidenceRef: z.string().max(300), confidence: z.number().min(0).max(1),
  severity: z.enum(['low', 'medium', 'high']), firstSeen: timestamp, lastVerified: timestamp,
  expiresAt: timestamp, version: z.number().int().positive(), revoked: z.boolean(),
});
export type IntelligenceIndicator = z.infer<typeof IndicatorSchema>;
// Source metadata is shared on the wire, avoiding repetition for large domain feeds.
export const BatchSchema = z.strictObject({
  source: Source, retrievedAt: timestamp, expiresAt: timestamp,
  records: z.array(z.tuple([z.string().min(1).max(1800), timestamp, z.string().max(100)])).max(200000),
});
export const RulesSchema = z.strictObject({
  schema: z.literal(2), channel: z.literal('stable'), version: z.number().int().positive().max(Number.MAX_SAFE_INTEGER),
  issuedAt: timestamp, expiresAt: timestamp, sources: z.array(BatchSchema).max(2),
  revocations: z.array(z.strictObject({ source: Source, value: z.string().max(1800), revokedAt: timestamp, reason: z.string().min(1).max(180) })).max(10000),
});
export type SourceBatch = z.infer<typeof BatchSchema>;
export type RemoteRuleset = z.infer<typeof RulesSchema>;
export type SignedEnvelope = { keyId: string; payload: string; signature: string };
export type Trust = { endpoint: string; keyId: string; publicKey: string; minimumVersion: number };
const EnvelopeSchema = z.strictObject({ keyId: z.string().min(1).max(80), payload: z.string().max(MAX_UPDATE_BYTES), signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/) });

export function normalizedDomain(value: string): string {
  if (!value || /[\s/@?#\\:]/.test(value) || value.length > 253) throw new Error('Invalid domain');
  const host = new URL(`https://${value}`).hostname.toLowerCase().replace(/\.$/, '');
  const result = parse(host, { allowPrivateDomains: true });
  if (!result.domain || result.isIp || (!result.isIcann && !result.isPrivate) || !host.split('.').every(p => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(p))) throw new Error('Domain is not a registrable public hostname');
  return host;
}
export function normalizedUrl(value: string): string {
  if (value.length > 1800 || /[\s\\]/.test(value)) throw new Error('Invalid URL indicator');
  const url = new URL(value);
  if (!['https:', 'http:'].includes(url.protocol) || url.username || url.password || url.hash) throw new Error('Invalid URL indicator');
  normalizedDomain(url.hostname);
  return url.href;
}
export function validateRemote(input: unknown): RemoteRuleset {
  const rules = RulesSchema.parse(input);
  const issued = Date.parse(rules.issuedAt), expires = Date.parse(rules.expiresAt);
  if (expires <= issued || expires - issued > MAX_SOURCE_AGE) throw new Error('Invalid ruleset lifetime');
  const sources = new Set<string>();
  for (const batch of rules.sources) {
    if (sources.has(batch.source)) throw new Error('Duplicate source');
    sources.add(batch.source);
    const retrieved = Date.parse(batch.retrievedAt), until = Date.parse(batch.expiresAt);
    if (retrieved > issued || until <= retrieved || until - retrieved > MAX_SOURCE_AGE || until > expires) throw new Error('Invalid source lifetime');
    if (batch.source === 'urlhaus' && batch.records.length > 800) throw new Error('URL rule capacity exceeded');
    const seen = new Set<string>();
    for (const [value, firstSeen, evidence] of batch.records) {
      const normalized = batch.source === 'cert-pl' ? normalizedDomain(value) : normalizedUrl(value);
      if (normalized !== value || seen.has(value) || Date.parse(firstSeen) > retrieved || !/^[a-zA-Z0-9_-]{1,100}$/.test(evidence)) throw new Error('Invalid source record');
      seen.add(value);
    }
  }
  for (const revocation of rules.revocations) {
    const normalized = revocation.source === 'cert-pl' ? normalizedDomain(revocation.value) : normalizedUrl(revocation.value);
    if (normalized !== revocation.value || Date.parse(revocation.revokedAt) > issued) throw new Error('Invalid revocation');
  }
  return rules;
}
function bytes(base64: string): Uint8Array<ArrayBuffer> { return Uint8Array.from(atob(base64), c => c.charCodeAt(0)); }
export async function digest(value: string): Promise<string> {
  const result = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(result), b => b.toString(16).padStart(2, '0')).join('');
}
export async function verifyEnvelope(input: unknown, trust: Trust, highWater = 0, expectedHash?: string, now = Date.now(), cached = false): Promise<{ rules: RemoteRuleset; envelope: SignedEnvelope; hash: string }> {
  const envelope = EnvelopeSchema.parse(input);
  if (envelope.keyId !== trust.keyId) throw new Error('Untrusted signing key');
  const key = await crypto.subtle.importKey('spki', bytes(trust.publicKey), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['verify']);
  const valid = await crypto.subtle.verify({ name: 'ECDSA', hash: 'SHA-256' }, key, bytes(envelope.signature), new TextEncoder().encode(envelope.payload));
  if (!valid) throw new Error('Ruleset signature rejected');
  const rules = validateRemote(JSON.parse(envelope.payload));
  const hash = await digest(envelope.payload);
  if (rules.version < Math.max(highWater, trust.minimumVersion) || (rules.version === highWater && expectedHash && hash !== expectedHash)) throw new Error('Ruleset replay or version conflict');
  if (Date.parse(rules.issuedAt) > now + 60000 || (!cached && Date.parse(rules.expiresAt) <= now)) throw new Error('Ruleset expired or clock incorrect');
  return { rules, envelope, hash };
}
export async function boundedText(response: Response, limit = MAX_UPDATE_BYTES): Promise<string> {
  if (!response.ok || !response.body || Number(response.headers.get('content-length')) > limit) throw new Error('Feed response rejected');
  const reader = response.body.getReader(), chunks: Uint8Array[] = [];
  let length = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      length += value.length;
      if (length > limit) throw new Error('Feed exceeds size limit');
      chunks.push(value);
    }
  } finally { await reader.cancel().catch(() => undefined); }
  const output = new Uint8Array(length); let position = 0;
  for (const chunk of chunks) { output.set(chunk, position); position += chunk.length; }
  return new TextDecoder('utf-8', { fatal: true }).decode(output);
}
export function effectiveBatches(rules: RemoteRuleset | undefined, now = Date.now()): SourceBatch[] {
  if (!rules || Date.parse(rules.expiresAt) <= now) return [];
  return rules.sources.filter(b => Date.parse(b.expiresAt) > now).map(b => {
    const revoked = new Set(rules.revocations.filter(r => r.source === b.source).map(r => r.value));
    return { ...b, records: b.records.filter(r => !revoked.has(r[0])) };
  });
}
export function indicator(batch: SourceBatch, row: SourceBatch['records'][number], version: number): IntelligenceIndicator {
  return { type: batch.source === 'cert-pl' ? 'domain' : 'url', value: row[0], classification: batch.source === 'cert-pl' ? 'phishing' : 'malware',
    status: 'confirmed', source: batch.source, evidenceRef: batch.source === 'cert-pl' ? `CERT-PL:${row[2]}` : `https://urlhaus.abuse.ch/url/${row[2]}/`, confidence: 0.95,
    severity: 'high', firstSeen: row[1], lastVerified: batch.retrievedAt, expiresAt: batch.expiresAt, version, revoked: false };
}
const indexes = new WeakMap<RemoteRuleset, Map<string, { batch: SourceBatch; row: SourceBatch['records'][number] }>>();
export function matchRemote(input: string, rules: RemoteRuleset | undefined, now = Date.now()): IntelligenceIndicator | undefined {
  if (!rules || Date.parse(rules.expiresAt) <= now) return;
  let url: URL;
  try { url = new URL(input.includes('://') ? input : `https://${input}/`); } catch { return; }
  if (!['http:', 'https:'].includes(url.protocol)) return;
  url.hash = ''; url.username = ''; url.password = '';
  let index = indexes.get(rules);
  if (!index) {
    index = new Map();
    for (const batch of rules.sources) for (const row of batch.records) index.set(`${batch.source}:${row[0]}`, { batch, row });
    for (const r of rules.revocations) index.delete(`${r.source}:${r.value}`);
    indexes.set(rules, index);
  }
  const candidates = [`urlhaus:${url.href}`];
  const labels = url.hostname.toLowerCase().replace(/\.$/, '').split('.');
  while (labels.length > 1) { candidates.push(`cert-pl:${labels.join('.')}`); labels.shift(); }
  for (const key of candidates) {
    const found = index.get(key);
    if (found && Date.parse(found.batch.expiresAt) > now) return indicator(found.batch, found.row, rules.version);
  }
}
export const resourceTypes = ['main_frame', 'sub_frame', 'stylesheet', 'script', 'image', 'font', 'object', 'xmlhttprequest', 'ping', 'csp_report', 'media', 'websocket', 'webtransport', 'webbundle', 'other'] as chrome.declarativeNetRequest.ResourceType[];
export function compileRemote(rules: RemoteRuleset | undefined, now = Date.now()): chrome.declarativeNetRequest.Rule[] {
  const result: chrome.declarativeNetRequest.Rule[] = [];
  let id = 2000000;
  for (const batch of effectiveBatches(rules, now)) {
    if (batch.source === 'cert-pl') {
      for (let offset = 0; offset < batch.records.length; offset += 1000) result.push({ id: ++id, priority: 1, action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType }, condition: { requestDomains: batch.records.slice(offset, offset + 1000).map(r => r[0]), resourceTypes } });
    } else for (const [value] of batch.records) result.push({ id: ++id, priority: 1, action: { type: 'block' as chrome.declarativeNetRequest.RuleActionType }, condition: { regexFilter: `^${value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}$`, isUrlFilterCaseSensitive: true, resourceTypes } });
  }
  return result;
}
