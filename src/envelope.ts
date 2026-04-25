import { z } from 'zod';
import canonicalize from 'canonicalize';

export const EnvelopeSchema = z.object({
  stream_id: z.number().int().nonnegative(),
  type: z.enum(['req', 'res', 'stream_chunk', 'stream_end', 'cancel', 'error']),
  seq: z.number().int().nonnegative(),
  credits: z.number().int().nonnegative().optional(),
  method: z.string().optional(),
  params: z.unknown().optional(),
  result: z.unknown().optional(),
  reason: z.string().optional(),
  error: z.object({ code: z.number().int(), message: z.string() }).optional(),
});

export type Envelope = z.infer<typeof EnvelopeSchema>;

export function encode(env: Envelope): Uint8Array {
  EnvelopeSchema.parse(env);
  const s = canonicalize(env);
  if (typeof s !== 'string') {
    throw new Error('canonicalize returned non-string');
  }
  return new TextEncoder().encode(s);
}

export function decode(bytes: Uint8Array): Envelope {
  const text = new TextDecoder().decode(bytes);
  return EnvelopeSchema.parse(JSON.parse(text));
}
