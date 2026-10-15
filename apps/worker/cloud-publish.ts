import { readFile } from 'node:fs/promises';
import { gzipSync, gunzipSync } from 'node:zlib';
import { Publisher, atomicWrite } from './publisher';
import { MAX_UPDATE_BYTES, verifyEnvelope, type Trust } from '../../packages/intelligence/index';

const keyPath = process.env.TWB_SIGNING_KEY_FILE;
const publicConfig = process.env.TWB_RELEASE_CONFIG;
if (!keyPath || !publicConfig) throw new Error('Private key file and public release config are required');
const trust = JSON.parse(await readFile(publicConfig, 'utf8')) as Trust;
const material = JSON.parse(await readFile(keyPath, 'utf8')) as { keyId: string; privateKey: string; publicKey: string };
if (material.keyId !== trust.keyId || material.publicKey !== trust.publicKey) throw new Error('Signing key differs from the release trust root');
const directory = process.env.TWB_DATA_DIR ?? 'service-data';
const publisher = new Publisher({ directory, privateKey: material.privateKey, trust });
const account = process.env.CLOUDFLARE_ACCOUNT_ID, namespace = process.env.TWB_KV_NAMESPACE_ID, token = process.env.CLOUDFLARE_API_TOKEN;
if (!account || !/^[a-f0-9]{32}$/.test(account) || !namespace || !/^[a-f0-9]{32}$/.test(namespace) || !token) throw new Error('Cloudflare publisher credentials/configuration missing');
const kvUrl = `https://api.cloudflare.com/client/v4/accounts/${account}/storage/kv/namespaces/${namespace}/values/current`;
// Rehydrate the last deployment on an ephemeral CI runner, validating its signature.
// A failed fetch must not be treated as an empty prior history on normal runs.
const response = await fetch(kvUrl, { headers: { authorization: `Bearer ${token}` }, redirect: 'error', credentials: 'omit', signal: AbortSignal.timeout(25000) });
if (response.ok) {
  if (Number(response.headers.get('content-length')) > 25 * 1024 * 1024) throw new Error('Stored snapshot exceeds capacity');
  const content = gunzipSync(await response.arrayBuffer(), { maxOutputLength: MAX_UPDATE_BYTES }).toString('utf8');
  const verified = await verifyEnvelope(JSON.parse(content), trust, 0, undefined, Date.now(), true);
  await atomicWrite(`${directory}/current.json`, JSON.stringify(verified.envelope));
} else if (response.status !== 404 || process.env.TWB_BOOTSTRAP !== 'yes') {
  throw new Error('Previous publication unavailable; explicit bootstrap is required to start or recover');
}
await atomicWrite(`${directory}/revocations.json`, await readFile('deploy/revocations.json', 'utf8'));
await publisher.load();
const previousVersion = publisher.current?.version;
await publisher.refresh();
if (!publisher.current || !publisher.envelope || publisher.current.version === previousVersion) throw new Error('Source refresh failed; no deployment produced');
const serialized = JSON.stringify(publisher.envelope), compressed = gzipSync(serialized);
if (compressed.length > 25 * 1024 * 1024) throw new Error('Snapshot exceeds delivery capacity');
const sourceExpiresAt = new Date(Math.max(0, ...publisher.current.sources.filter(b => b.records.length > 0).map(b => Date.parse(b.expiresAt)))).toISOString();
const metadata = { version: publisher.current.version, expiresAt: publisher.current.expiresAt, sourceExpiresAt, count: publisher.current.sources.reduce((n, b) => n + b.records.length, 0), encoding: 'gzip' };
async function upload(key: 'current' | 'delta', bytes: Uint8Array<ArrayBuffer>, details: Record<string, unknown>): Promise<void> {
  const form = new FormData();
  form.set('value', new Blob([bytes]), 'ruleset.gz'); form.set('metadata', JSON.stringify(details));
  const uploaded = await fetch(kvUrl.replace(/current$/, key), { method: 'PUT', headers: { authorization: `Bearer ${token}` }, body: form, signal: AbortSignal.timeout(25000), redirect: 'error' });
  const result = await uploaded.json() as { success?: boolean };
  if (!uploaded.ok || !result.success) throw new Error('Delivery publication failed');
}
let deltaBytes = 0, deltaBaseVersion: number | undefined;
if (publisher.delta) {
  const delta = gzipSync(JSON.stringify(publisher.delta));
  if (delta.length < compressed.length) {
    // Publish the optional delta first. A partial failure leaves the prior full
    // publication authoritative; delivery validates both generations before use.
    try {
      await upload('delta', delta, { ...metadata, baseVersion: publisher.delta.baseVersion });
      deltaBytes = delta.length; deltaBaseVersion = publisher.delta.baseVersion;
    } catch { /* Optional transport failure must not prevent a fresh full publication. */ }
  }
}
await upload('current', compressed, { ...metadata, ...(deltaBaseVersion ? { deltaBaseVersion } : {}) });
console.log(JSON.stringify({ event: 'published', version: publisher.current.version, sources: publisher.sourceHealth, compressedBytes: compressed.length, deltaBytes, deltaBaseVersion }));
