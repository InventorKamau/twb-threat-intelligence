// The free edge tier streams pre-signed data. Parsing, validation and signing run
// in the publisher, outside the edge CPU limit. No private key lives here.
import { refreshAgingPublication } from './scheduler';
export type Metadata = { version: number; expiresAt: string; sourceExpiresAt?: string; count: number; encoding: 'gzip'; deltaBaseVersion?: number; baseVersion?: number };
export type DeliveryEnv = { TWB_GITHUB_DISPATCH_TOKEN?: string; TWB_RULESETS: { getWithMetadata(key: string, options: { type: 'stream'; cacheTtl: number }): Promise<{ value: ReadableStream<Uint8Array> | null; metadata: Metadata | null }> } };
export default {
  async scheduled(_event: unknown, env: DeliveryEnv): Promise<void> {
    await refreshAgingPublication(env);
  },
  async fetch(request: Request, env: DeliveryEnv): Promise<Response> {
    const url = new URL(request.url);
    const headers = new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
    if (url.search || !['GET', 'HEAD'].includes(request.method)) return new Response('{"error":"Unsupported request"}', { status: 400, headers });
    if (!['/v1/ruleset', '/v1/update', '/healthz'].includes(url.pathname)) return new Response('{"error":"Not found"}', { status: 404, headers });
    try {
      const { value, metadata } = await env.TWB_RULESETS.getWithMetadata('current', { type: 'stream', cacheTtl: 60 });
      if (!value || !metadata || !Number.isSafeInteger(metadata.version) || metadata.encoding !== 'gzip' || !Number.isFinite(Date.parse(metadata.expiresAt)) || Date.parse(metadata.expiresAt) <= Date.now()) {
        await value?.cancel();
        return new Response('{"status":"degraded","error":"No fresh signed intelligence"}', { status: 503, headers });
      }
      if (url.pathname === '/healthz') {
        await value.cancel();
        const sourceExpiresAt = metadata.sourceExpiresAt ?? metadata.expiresAt;
        const fresh = metadata.count > 0 && Date.parse(sourceExpiresAt) > Date.now();
        return new Response(request.method === 'HEAD' ? null : JSON.stringify({ status: fresh ? 'ready' : 'degraded', version: metadata.version, expiresAt: metadata.expiresAt, sourceExpiresAt, indicators: metadata.count }), { status: fresh ? 200 : 503, headers });
      }
      const etag = `"twb-${metadata.version}"`;
      const updates = url.pathname === '/v1/update';
      headers.set('etag', etag); headers.set('cache-control', updates ? 'no-store' : 'public, max-age=60, must-revalidate');
      headers.set('vary', 'If-None-Match');
      if (request.headers.get('if-none-match') === etag) { await value.cancel(); return new Response(null, { status: 304, headers }); }
      let body = value;
      headers.set('x-twb-format', 'snapshot');
      if (updates && Number.isSafeInteger(metadata.deltaBaseVersion) && request.headers.get('if-none-match') === `"twb-${metadata.deltaBaseVersion}"`) {
        // Read current first: eventually consistent KV may expose mismatched
        // generations. Never select a delta without matching authoritative metadata.
        try {
          const delta = await env.TWB_RULESETS.getWithMetadata('delta', { type: 'stream', cacheTtl: 60 });
          if (delta.value && delta.metadata?.version === metadata.version && delta.metadata.baseVersion === metadata.deltaBaseVersion && delta.metadata.expiresAt === metadata.expiresAt && delta.metadata.encoding === 'gzip') {
            await value.cancel(); body = delta.value; headers.set('x-twb-format', 'delta');
          } else await delta.value?.cancel();
        } catch { /* Full snapshot remains usable when delta storage is unavailable. */ }
      }
      headers.set('content-encoding', 'gzip');
      if (request.method === 'HEAD') { await body.cancel(); return new Response(null, { headers }); }
      // KV already contains gzip bytes. Workers otherwise compresses this body
      // again, leaving clients with compressed bytes after HTTP decoding.
      const options: ResponseInit & { encodeBody: 'manual' } = { headers, encodeBody: 'manual' };
      return new Response(body, options);
    } catch { return new Response('{"status":"degraded","error":"Intelligence storage unavailable"}', { status: 503, headers }); }
  },
};
