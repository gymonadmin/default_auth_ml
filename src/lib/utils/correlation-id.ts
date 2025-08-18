// src/lib/utils/correlation-id.ts
import { v4 as uuidv4 } from 'uuid';

export function generateCorrelationId(): string {
  return uuidv4();
}

export function validateCorrelationId(id: string): boolean {
  const uuidRegex = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i;
  return uuidRegex.test(id);
}

export function getCorrelationIdFromHeaders(headers: Headers): string | null {
  return headers.get('x-correlation-id') || null;
}

export function setCorrelationIdHeader(headers: Headers, correlationId: string): void {
  headers.set('x-correlation-id', correlationId);
}
