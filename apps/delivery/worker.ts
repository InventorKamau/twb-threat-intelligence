// The free edge tier streams pre-signed data. Parsing, validation and signing run
// in the publisher, outside the edge CPU limit. No private key lives here.
import { refreshAgingPublication } from './scheduler';
export type Metadata = { version: number; expiresAt: string; count: number; encoding: 'gzip' };
export type DeliveryEnv = { TWB_GITHUB_DISPATCH_TOKEN?: string; TWB_RULESETS: { getWithMetadata(key: string, options: { type: 'stream'; cacheTtl: number }): Promise<{ value: ReadableStream<Uint8Array> | null; metadata: Metadata | null }> } };
export default {
  async scheduled(_event: unknown, env: DeliveryEnv): Promise<void> {
    await refreshAgingPublication(env);
  },
  async fetch(request: Request, env: DeliveryEnv): Promise<Response> {
    const url = new URL(request.url);
    const headers = new Headers({ 'content-type': 'application/json', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff', 'referrer-policy': 'no-referrer' });
    if (url.search || !['GET', 'HEAD'].includes(request.method)) return new Response('{"error":"Unsupported request"}', { status: 400, headers });
    if (!['/v1/ruleset', '/healthz'].includes(url.pathname)) return new Response('{"error":"Not found"}', { status: 404, headers });
    try {
      const { value, metadata } = await env.TWB_RULESETS.getWithMetadata('current', { type: 'stream', cacheTtl: 60 });
      if (!value || !metadata || !Number.isSafeInteger(metadata.version) || metadata.encoding !== 'gzip' || !Number.isFinite(Date.parse(metadata.expiresAt)) || Date.parse(metadata.expiresAt) <= Date.now()) {
        await value?.cancel();
        return new Response('{"status":"degraded","error":"No fresh signed intelligence"}', { status: 503, headers });
      }
      if (url.pathname === '/healthz') {
        await value.cancel();
        return new Response(request.method === 'HEAD' ? null : JSON.stringify({ status: 'ready', version: metadata.version, expiresAt: metadata.expiresAt, indicators: metadata.count }), { headers });
      }
      const etag = `"twb-${metadata.version}"`;
      headers.set('etag', etag); headers.set('cache-control', 'public, max-age=60, must-revalidate');
      if (request.headers.get('if-none-match') === etag) { await value.cancel(); return new Response(null, { status: 304, headers }); }
      headers.set('content-encoding', 'gzip');
      if (request.method === 'HEAD') { await value.cancel(); return new Response(null, { headers }); }
      // KV already contains gzip bytes. Workers otherwise compresses this body
      // again, leaving clients with compressed bytes after HTTP decoding.
      const options: ResponseInit & { encodeBody: 'manual' } = { headers, encodeBody: 'manual' };
      return new Response(value, options);
    } catch { return new Response('{"status":"degraded","error":"Intelligence storage unavailable"}', { status: 503, headers }); }
  },
};
