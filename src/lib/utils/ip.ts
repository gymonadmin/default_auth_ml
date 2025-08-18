// src/lib/utils/ip.ts
import { NextRequest } from 'next/server';

/**
 * Extract client IP address from request headers
 */
export function getClientIP(request: NextRequest): string | null {
  // Check common proxy headers in order of preference
  const headers = [
    'x-forwarded-for',
    'x-real-ip',
    'x-client-ip',
    'x-forwarded',
    'x-cluster-client-ip',
    'forwarded-for',
    'forwarded',
  ];

  for (const header of headers) {
    const value = request.headers.get(header);
    if (value) {
      // x-forwarded-for can contain multiple IPs, take the first one
      const ip = value.split(',')[0].trim();
      if (isValidIP(ip)) {
        return ip;
      }
    }
  }

  // Fallback to connection remote address
  const remoteAddress = request.ip;
  if (remoteAddress && isValidIP(remoteAddress)) {
    return remoteAddress;
  }

  return null;
}

/**
 * Validate IP address format (IPv4 or IPv6)
 */
export function isValidIP(ip: string): boolean {
  return isValidIPv4(ip) || isValidIPv6(ip);
}

/**
 * Validate IPv4 address format
 */
export function isValidIPv4(ip: string): boolean {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

/**
 * Validate IPv6 address format
 */
export function isValidIPv6(ip: string): boolean {
  const ipv6Regex = /^(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$|^::1$|^::$/;
  return ipv6Regex.test(ip);
}

/**
 * Check if IP is a private/internal address
 */
export function isPrivateIP(ip: string): boolean {
  if (!isValidIPv4(ip)) {
    // For IPv6, we'll consider loopback and link-local as private
    if (ip === '::1' || ip.startsWith('fe80:')) {
      return true;
    }
    return false;
  }

  const parts = ip.split('.').map(Number);
  
  // Check private IPv4 ranges
  return (
    // 10.0.0.0/8
    parts[0] === 10 ||
    // 172.16.0.0/12
    (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) ||
    // 192.168.0.0/16
    (parts[0] === 192 && parts[1] === 168) ||
    // 127.0.0.0/8 (loopback)
    parts[0] === 127 ||
    // 169.254.0.0/16 (link-local)
    (parts[0] === 169 && parts[1] === 254)
  );
}

/**
 * Check if IP is localhost
 */
export function isLocalhost(ip: string): boolean {
  if (!ip) return false;
  
  return (
    ip === '127.0.0.1' ||
    ip === '::1' ||
    ip === 'localhost'
  );
}

/**
 * Anonymize IP address for logging (remove last octet for IPv4)
 */
export function anonymizeIP(ip: string): string {
  if (!ip || !isValidIP(ip)) {
    return 'unknown';
  }

  if (isValidIPv4(ip)) {
    const parts = ip.split('.');
    parts[3] = 'xxx';
    return parts.join('.');
  }

  if (isValidIPv6(ip)) {
    // For IPv6, mask the last 64 bits
    const parts = ip.split(':');
    if (parts.length >= 4) {
      for (let i = Math.max(0, parts.length - 4); i < parts.length; i++) {
        parts[i] = 'xxxx';
      }
    }
    return parts.join(':');
  }

  return 'unknown';
}

/**
 * Get IP version (4 or 6)
 */
export function getIPVersion(ip: string): 4 | 6 | null {
  if (isValidIPv4(ip)) return 4;
  if (isValidIPv6(ip)) return 6;
  return null;
}

/**
 * Format IP address for database storage
 */
export function formatIPForStorage(ip: string | null): string | null {
  if (!ip) return null;
  
  // Clean and validate the IP
  const cleanIP = ip.trim();
  if (!isValidIP(cleanIP)) return null;
  
  return cleanIP;
}

/**
 * Extract IP from various header formats
 */
export function parseIPFromHeader(headerValue: string): string | null {
  if (!headerValue) return null;
  
  // Handle comma-separated IPs (x-forwarded-for)
  const ips = headerValue.split(',').map(ip => ip.trim());
  
  for (const ip of ips) {
    // Skip private IPs unless it's the only option
    if (isValidIP(ip) && !isPrivateIP(ip)) {
      return ip;
    }
  }
  
  // If no public IP found, return the first valid IP
  for (const ip of ips) {
    if (isValidIP(ip)) {
      return ip;
    }
  }
  
  return null;
}
