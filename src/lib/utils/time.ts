// src/lib/utils/time.ts

/**
 * Get current UTC timestamp
 */
export function getCurrentUTC(): Date {
  return new Date();
}

/**
 * Add seconds to a date and return new Date
 */
export function addSeconds(date: Date, seconds: number): Date {
  const newDate = new Date(date);
  newDate.setSeconds(newDate.getSeconds() + seconds);
  return newDate;
}

/**
 * Add minutes to a date and return new Date
 */
export function addMinutes(date: Date, minutes: number): Date {
  return addSeconds(date, minutes * 60);
}

/**
 * Add hours to a date and return new Date
 */
export function addHours(date: Date, hours: number): Date {
  return addMinutes(date, hours * 60);
}

/**
 * Add days to a date and return new Date
 */
export function addDays(date: Date, days: number): Date {
  return addHours(date, days * 24);
}

/**
 * Check if a date is in the past
 */
export function isPast(date: Date): boolean {
  return date.getTime() < getCurrentUTC().getTime();
}

/**
 * Check if a date is in the future
 */
export function isFuture(date: Date): boolean {
  return date.getTime() > getCurrentUTC().getTime();
}

/**
 * Get the difference in seconds between two dates
 */
export function getDifferenceInSeconds(date1: Date, date2: Date): number {
  return Math.floor((date1.getTime() - date2.getTime()) / 1000);
}

/**
 * Get the difference in minutes between two dates
 */
export function getDifferenceInMinutes(date1: Date, date2: Date): number {
  return Math.floor(getDifferenceInSeconds(date1, date2) / 60);
}

/**
 * Get the difference in hours between two dates
 */
export function getDifferenceInHours(date1: Date, date2: Date): number {
  return Math.floor(getDifferenceInMinutes(date1, date2) / 60);
}

/**
 * Format a date to ISO string (UTC)
 */
export function toISOString(date: Date): string {
  return date.toISOString();
}

/**
 * Parse ISO string to Date
 */
export function fromISOString(isoString: string): Date {
  return new Date(isoString);
}

/**
 * Create a date that expires after specified seconds from now
 */
export function createExpirationDate(seconds: number): Date {
  return addSeconds(getCurrentUTC(), seconds);
}

/**
 * Get seconds until expiration (returns 0 if already expired)
 */
export function getSecondsUntilExpiration(expirationDate: Date): number {
  const secondsLeft = getDifferenceInSeconds(expirationDate, getCurrentUTC());
  return Math.max(0, secondsLeft);
}

/**
 * Check if a date has expired
 */
export function hasExpired(expirationDate: Date): boolean {
  return isPast(expirationDate);
}

/**
 * Get human-readable time difference
 */
export function getHumanReadableTimeDiff(date: Date): string {
  const now = getCurrentUTC();
  const diffSeconds = Math.abs(getDifferenceInSeconds(now, date));
  const isPastDate = isPast(date);
  const suffix = isPastDate ? 'ago' : 'from now';
  
  if (diffSeconds < 60) {
    return `${diffSeconds} second${diffSeconds !== 1 ? 's' : ''} ${suffix}`;
  }
  
  const diffMinutes = Math.floor(diffSeconds / 60);
  if (diffMinutes < 60) {
    return `${diffMinutes} minute${diffMinutes !== 1 ? 's' : ''} ${suffix}`;
  }
  
  const diffHours = Math.floor(diffMinutes / 60);
  if (diffHours < 24) {
    return `${diffHours} hour${diffHours !== 1 ? 's' : ''} ${suffix}`;
  }
  
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays} day${diffDays !== 1 ? 's' : ''} ${suffix}`;
}

/**
 * Constants for common time durations in seconds
 */
export const TIME_CONSTANTS = {
  SECOND: 1,
  MINUTE: 60,
  HOUR: 60 * 60,
  DAY: 24 * 60 * 60,
  WEEK: 7 * 24 * 60 * 60,
  MONTH: 30 * 24 * 60 * 60,
  YEAR: 365 * 24 * 60 * 60,
} as const;
