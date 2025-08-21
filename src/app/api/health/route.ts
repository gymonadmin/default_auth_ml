// src/app/api/health/route.ts
import { NextResponse } from 'next/server';
import { setCSPHeaders } from '@/lib/utils/csp';

export async function GET() {
  const response = NextResponse.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
  });
  
  setCSPHeaders(response.headers);
  return response;
}

export async function HEAD() {
  const response = new NextResponse(null, { status: 200 });
  setCSPHeaders(response.headers);
  return response;
}

// Handle unsupported methods
export async function POST() {
  const response = NextResponse.json(
    { error: 'Method not allowed' },
    { status: 405, headers: { 'Allow': 'GET, HEAD' } }
  );
  setCSPHeaders(response.headers);
  return response;
}
