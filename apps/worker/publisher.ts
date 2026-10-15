import { webcrypto } from 'node:crypto';
import { readFile, mkdir, open, rename } from 'node:fs/promises';
import path from 'node:path';
import { validateRemote, verifyEnvelope, MAX_SOURCE_AGE, type RemoteRuleset, type SignedEnvelope, type SourceBatch, type Trust } from '../../packages/intelligence/index';
import { CERT_ENDPOINT, certBatch, checkedUrlhausEndpoint, download, urlhausBatch } from './feeds';

export async function atomicWrite(file: string, content: string): Promise<void> {
  await mkdir(path.dirname(file), { recursive: true });
  const temporary = `${file}.${process.pid}.tmp`;
  const handle = await open(temporary, 'w', 0o600);
  try { await handle.writeFile(content); await handle.sync(); } finally { await handle.close(); }
  await rename(temporary, file);
}
export async function signRules(rules: RemoteRuleset, privateKey: string, keyId: string): Promise<SignedEnvelope> {
  validateRemote(rules);
  const key = await webcrypto.subtle.importKey('pkcs8', Buffer.from(privateKey, 'base64'), { name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign']);
  const payload = JSON.stringify(rules);
  const signature = await webcrypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, key, new TextEncoder().encode(payload));
  return { keyId, payload, signature: Buffer.from(signature).toString('base64') };
}
type PublisherOptions = { directory: string; privateKey: string; trust: Trust; urlhausEndpoint?: string; fetcher?: typeof fetch };
type SourceHealth = { source: string; ok: boolean; count: number; omitted: number };
export class Publisher {
  current?: RemoteRuleset;
  envelope?: SignedEnvelope;
  sourceHealth: SourceHealth[] = [];
  lastAttempt?: string;
  busy = false;
  constructor(private options: PublisherOptions) {}
  async load(): Promise<void> {
    try {
      const input: unknown = JSON.parse(await readFile(path.join(this.options.directory, 'current.json'), 'utf8'));
      const verified = await verifyEnvelope(input, this.options.trust, 0, undefined, Date.now(), true);
      this.current = verified.rules; this.envelope = verified.envelope;
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('Persisted publication invalid; restore the durable volume before starting', { cause: error });
    }
  }
  async refresh(): Promise<void> {
    if (this.busy) return;
    this.busy = true;
    try {
      this.lastAttempt = new Date().toISOString();
      const batches: SourceBatch[] = []; const health: SourceHealth[] = [];
      const sources = ['cert-pl', ...(this.options.urlhausEndpoint ? ['urlhaus'] : [])] as const;
      for (const source of sources) {
        const previous = this.current?.sources.find(b => b.source === source);
        try {
          const endpoint = source === 'cert-pl' ? CERT_ENDPOINT : checkedUrlhausEndpoint(this.options.urlhausEndpoint!);
          const text = await download(endpoint, this.options.fetcher);
          const result = source === 'cert-pl' ? { batch: certBatch(text, previous), omitted: 0 } : urlhausBatch(text);
          // Do not silently publish a truncated or unexpectedly empty domain export.
          if (previous && source === 'cert-pl' && result.batch.records.length < previous.records.length / 2) throw new Error('Large source shrink requires operator review');
          batches.push(result.batch); health.push({ source, ok: true, count: result.batch.records.length, omitted: result.omitted });
        } catch {
          // Never put credential-bearing URLs or response bodies into logs/status.
          if (previous && Date.parse(previous.expiresAt) > Date.now()) batches.push(previous);
          health.push({ source, ok: false, count: previous?.records.length ?? 0, omitted: 0 });
        }
      }
      this.sourceHealth = health;
      const now = Date.now();
      const revocationsFile = path.join(this.options.directory, 'revocations.json');
      let revocations: unknown = [];
      try { revocations = JSON.parse(await readFile(revocationsFile, 'utf8')); }
      catch (error) { if ((error as NodeJS.ErrnoException).code !== 'ENOENT') throw new Error('Invalid operator revocations', { cause: error }); }
      const revocationsChanged = this.current && JSON.stringify(revocations) !== JSON.stringify(this.current.revocations);
      if (!health.some(h => h.ok) && !revocationsChanged) return;
      const next = validateRemote({ schema: 2, channel: 'stable', version: Math.max(now, (this.current?.version ?? 0) + 1), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + MAX_SOURCE_AGE).toISOString(), sources: batches, revocations });
      await this.publish(next);
    } finally { this.busy = false; }
  }
  async publish(next: RemoteRuleset): Promise<void> {
    if (this.current && next.version <= this.current.version) throw new Error('Publication version must increase');
    const envelope = await signRules(next, this.options.privateKey, this.options.trust.keyId);
    await verifyEnvelope(envelope, this.options.trust, this.current?.version ?? 0);
    if (this.envelope) await atomicWrite(path.join(this.options.directory, 'previous.json'), JSON.stringify(this.envelope));
    await atomicWrite(path.join(this.options.directory, 'current.json'), JSON.stringify(envelope));
    this.current = next; this.envelope = envelope;
  }
  async rollback(): Promise<void> {
    if (!this.current) throw new Error('No current publication to roll back');
    const prior = JSON.parse(await readFile(path.join(this.options.directory, 'previous.json'), 'utf8')) as unknown;
    const verified = await verifyEnvelope(prior, this.options.trust, 0, undefined, Date.now(), true);
    await this.publish(safeRollback(verified.rules, this.current));
  }
}

// Rollback can remove new rules, but must never undo withdrawals or revocations.
// It is a new signed version; cached older envelopes remain forbidden to clients.
export function safeRollback(prior: RemoteRuleset, current: RemoteRuleset, now = Date.now()): RemoteRuleset {
  return validateRemote({ ...prior, version: Math.max(now, current.version + 1), issuedAt: new Date(now).toISOString(), expiresAt: new Date(now + MAX_SOURCE_AGE).toISOString(), revocations: current.revocations,
    sources: prior.sources.filter(b => Date.parse(b.expiresAt) > now).map(batch => {
      const active = new Set(current.sources.find(b => b.source === batch.source)?.records.map(row => row[0]));
      return { ...batch, records: batch.records.filter(row => active.has(row[0])) };
    }),
  });
}
