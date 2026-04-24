import { z } from 'zod';

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

export function encode(_env: Envelope): Uint8Array {
  throw new Error('not implemented');
}
export function decode(_bytes: Uint8Array): Envelope {
  throw new Error('not implemented');
}
