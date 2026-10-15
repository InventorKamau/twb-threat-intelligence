import { z } from 'zod';
import { BatchSchema, RulesSchema, MAX_UPDATE_BYTES, digest, validateRemote, verifyEnvelope, type RemoteRuleset, type SignedEnvelope, type Trust } from './index';

export const MAX_DELTA_BYTES = 2 * 1024 * 1024;
const RangeSchema = z.tuple([z.number().int().min(0).max(199999), z.number().int().min(1).max(200000)]);
const DeltaSchema = z.strictObject({
  kind: z.literal('twb-delta-1'), baseVersion: z.number().int().positive().max(Number.MAX_SAFE_INTEGER), baseHash: z.string().regex(/^[a-f0-9]{64}$/),
  keyId: z.string().min(1).max(80), signature: z.string().regex(/^[A-Za-z0-9+/]{86}==$/),
  target: RulesSchema.extend({ sources: z.array(BatchSchema.extend({ records: z.array(z.union([RangeSchema, BatchSchema.shape.records.element])).max(20000) })).max(2) }),
});
export type RulesDelta = z.infer<typeof DeltaSchema>;
type Verified = Awaited<ReturnType<typeof verifyEnvelope>>;

function reconstruct(input: unknown, base: Pick<Verified, 'rules' | 'hash'>): SignedEnvelope {
  if (new TextEncoder().encode(JSON.stringify(input)).byteLength > MAX_DELTA_BYTES) throw new Error('Delta exceeds size limit');
  const delta = DeltaSchema.parse(input);
  if (delta.baseVersion !== base.rules.version || delta.baseHash !== base.hash || delta.target.version <= delta.baseVersion) throw new Error('Delta baseline mismatch');
  const sources = delta.target.sources.map(batch => {
    const previous = base.rules.sources.find(b => b.source === batch.source)?.records ?? [];
    const records: RemoteRuleset['sources'][number]['records'] = [];
    const maximum = batch.source === 'urlhaus' ? 800 : 200000;
    const seen = new Set<string>();
    const append = (row: [string, string, string]) => {
      if (records.length >= maximum || seen.has(row[0])) throw new Error('Duplicate or excessive delta expansion');
      seen.add(row[0]); records.push(row);
    };
    for (const segment of batch.records) {
      if (typeof segment[0] === 'number') {
        const [start, count] = segment as [number, number];
        if (start + count > previous.length || records.length + count > maximum) throw new Error('Invalid delta range');
        // Bounded range copying preserves exact source order. No executable patch
        // expressions, property paths, or remotely supplied code are evaluated.
        for (let index = start; index < start + count; index++) append(previous[index]!);
      } else {
        append(segment as [string, string, string]);
      }
    }
    return { source: batch.source, retrievedAt: batch.retrievedAt, expiresAt: batch.expiresAt, records };
  });
  const rules = { schema: delta.target.schema, channel: delta.target.channel, version: delta.target.version, issuedAt: delta.target.issuedAt, expiresAt: delta.target.expiresAt, sources, revocations: delta.target.revocations };
  const payload = JSON.stringify(rules);
  if (new TextEncoder().encode(payload).byteLength > MAX_UPDATE_BYTES) throw new Error('Expanded ruleset exceeds size limit');
  return { keyId: delta.keyId, signature: delta.signature, payload };
}

// The baseline must already be signature-verified (an expired verified cache is
// allowed as a baseline). Only the final verified result may reach native rules.
export async function verifyUpdate(input: unknown, trust: Trust, base: Verified | undefined, highWater = 0, expectedHash?: string, now = Date.now()): Promise<Verified> {
  const isDelta = !!input && typeof input === 'object' && 'kind' in input && input.kind === 'twb-delta-1';
  if (isDelta && !base) throw new Error('Delta requires a verified baseline');
  const envelope = isDelta ? reconstruct(input, base!) : input;
  return verifyEnvelope(envelope, trust, highWater, expectedHash, now);
}

// The publisher only supplies verified previous/current envelopes here. Refuse
// a delta unless reconstruction reproduces the target's exact signed bytes.
export async function createDelta(previous: SignedEnvelope, next: SignedEnvelope): Promise<RulesDelta | undefined> {
  const base = validateRemote(JSON.parse(previous.payload)), target = validateRemote(JSON.parse(next.payload));
  if (target.version <= base.version || previous.keyId !== next.keyId) return;
  const sources = target.sources.map(batch => {
    const prior = base.sources.find(b => b.source === batch.source)?.records ?? [];
    const positions = new Map(prior.map((row, index) => [row[0], { row, index }]));
    const records: (typeof batch.records[number] | [number, number])[] = [];
    for (const row of batch.records) {
      const found = positions.get(row[0]);
      if (found && found.row[1] === row[1] && found.row[2] === row[2]) {
        const last = records.at(-1);
        if (last && typeof last[0] === 'number' && last[0] + (last[1] as number) === found.index) (last as [number, number])[1]++;
        else records.push([found.index, 1]);
      } else records.push(row);
    }
    return { ...batch, records };
  });
  const raw = { kind: 'twb-delta-1', baseVersion: base.version, baseHash: await digest(previous.payload), keyId: next.keyId, signature: next.signature, target: { ...target, sources } };
  const serialized = JSON.stringify(raw);
  if (new TextEncoder().encode(serialized).byteLength > MAX_DELTA_BYTES || serialized.length >= JSON.stringify(next).length * 0.8) return;
  const parsed = DeltaSchema.safeParse(raw);
  if (!parsed.success || reconstruct(parsed.data, { rules: base, hash: raw.baseHash }).payload !== next.payload) return;
  return parsed.data;
}
