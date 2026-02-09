/**
 * Protocol version for the zk-id system.
 *
 * This version is decoupled from npm package versions and only advances
 * when there are breaking changes to the wire format (proof structures,
 * public signals, or protocol messages).
 *
 * Format: zk-id/<major>.<minor>[-suffix]
 * - Major version changes indicate breaking protocol changes
 * - Minor version changes indicate backward-compatible additions
 * - Suffix (e.g., -draft, -rc1) indicates pre-release status
 */
export const PROTOCOL_VERSION = 'zk-id/1.0-draft';

/**
 * Parsed protocol version components
 */
export interface ParsedProtocolVersion {
  major: number;
  minor: number;
  suffix?: string;
}

/**
 * Lifecycle status of a protocol version.
 *
 * - `active`     — Fully supported. Clients and servers should use this version.
 * - `deprecated` — Still functional but scheduled for removal. Servers may
 *                  emit warnings. Clients should migrate to the successor.
 * - `sunset`     — No longer accepted by conforming servers. Requests using
 *                  this version SHOULD be rejected.
 */
export type ProtocolVersionStatus = 'active' | 'deprecated' | 'sunset';

/**
 * An entry in the protocol deprecation schedule.
 */
export interface ProtocolDeprecationEntry {
  /** Protocol version string (e.g., "zk-id/1.0-draft") */
  version: string;
  /** Current lifecycle status */
  status: ProtocolVersionStatus;
  /** ISO 8601 date when the version was or will be deprecated (optional for active) */
  deprecatedAt?: string;
  /** ISO 8601 date when the version was or will be sunset (rejected) */
  sunsetAt?: string;
  /** Protocol version that replaces this one (if deprecated or sunset) */
  successor?: string;
  /** Human-readable migration note */
  migrationNote?: string;
}

/**
 * Default deprecation schedule.
 *
 * Maintained in code so that SDK servers can enforce it programmatically.
 * As new protocol versions are released, entries are added here.
 */
export const DEPRECATION_SCHEDULE: ProtocolDeprecationEntry[] = [
  {
    version: 'zk-id/1.0-draft',
    status: 'active',
  },
];

/**
 * Default deprecation policy constants.
 */
export const DEPRECATION_POLICY = {
  /** Minimum time between deprecation announcement and sunset (days) */
  minDeprecationWindowDays: 90,
  /** Recommended migration lead time before sunset (days) */
  recommendedMigrationDays: 60,
  /** Sunset header name for HTTP responses */
  sunsetHeader: 'Sunset',
  /** Deprecation link header name */
  deprecationHeader: 'Deprecation',
  /** Link relation for migration docs */
  migrationLinkRel: 'sunset',
} as const;

/**
 * Parses a protocol version string into its components.
 *
 * @param version - Protocol version string (e.g., "zk-id/1.0-draft")
 * @returns Parsed version components
 * @throws Error if version format is invalid
 */
export function parseProtocolVersion(version: string): ParsedProtocolVersion {
  const match = version.match(/^zk-id\/(\d+)\.(\d+)(?:-(.+))?$/);

  if (!match) {
    throw new Error(`Invalid protocol version format: ${version}`);
  }

  return {
    major: parseInt(match[1], 10),
    minor: parseInt(match[2], 10),
    suffix: match[3],
  };
}

/**
 * Checks if two protocol versions are compatible.
 *
 * Versions are compatible if they share the same major version number.
 * Minor versions and suffixes do not affect compatibility.
 *
 * @param a - First protocol version
 * @param b - Second protocol version
 * @returns True if versions are compatible (same major version)
 */
export function isProtocolCompatible(a: string, b: string): boolean {
  try {
    const parsedA = parseProtocolVersion(a);
    const parsedB = parseProtocolVersion(b);

    return parsedA.major === parsedB.major;
  } catch {
    return false;
  }
}

/**
 * Looks up the deprecation status of a protocol version.
 *
 * @param version - Protocol version string
 * @param schedule - Deprecation schedule to check (defaults to DEPRECATION_SCHEDULE)
 * @returns The deprecation entry if found, or null if the version is not in the schedule
 */
export function getVersionStatus(
  version: string,
  schedule: ProtocolDeprecationEntry[] = DEPRECATION_SCHEDULE
): ProtocolDeprecationEntry | null {
  return schedule.find((e) => e.version === version) ?? null;
}

/**
 * Checks whether a protocol version has been deprecated (status is 'deprecated' or 'sunset').
 *
 * @param version - Protocol version string
 * @param schedule - Deprecation schedule to check
 * @returns true if the version is deprecated or sunset
 */
export function isVersionDeprecated(
  version: string,
  schedule: ProtocolDeprecationEntry[] = DEPRECATION_SCHEDULE
): boolean {
  const entry = getVersionStatus(version, schedule);
  if (!entry) return false;
  return entry.status === 'deprecated' || entry.status === 'sunset';
}

/**
 * Checks whether a protocol version has been sunset (should be rejected).
 *
 * @param version - Protocol version string
 * @param schedule - Deprecation schedule to check
 * @returns true if the version is sunset
 */
export function isVersionSunset(
  version: string,
  schedule: ProtocolDeprecationEntry[] = DEPRECATION_SCHEDULE
): boolean {
  const entry = getVersionStatus(version, schedule);
  if (!entry) return false;
  return entry.status === 'sunset';
}

/**
 * Builds HTTP headers for deprecation signaling (RFC 8594 / draft-ietf-httpapi-deprecation).
 *
 * Returns an object of header name/value pairs that servers should include
 * in responses when a client uses a deprecated or sunset version.
 *
 * @param entry - Deprecation entry for the client's protocol version
 * @param migrationUrl - Optional URL pointing to migration documentation
 * @returns Header name/value pairs (empty object if version is active)
 */
export function buildDeprecationHeaders(
  entry: ProtocolDeprecationEntry,
  migrationUrl?: string
): Record<string, string> {
  const headers: Record<string, string> = {};

  if (entry.status === 'active') return headers;

  if (entry.deprecatedAt) {
    headers[DEPRECATION_POLICY.deprecationHeader] = entry.deprecatedAt;
  }

  if (entry.sunsetAt) {
    headers[DEPRECATION_POLICY.sunsetHeader] = entry.sunsetAt;
  }

  if (migrationUrl) {
    headers['Link'] = `<${migrationUrl}>; rel="${DEPRECATION_POLICY.migrationLinkRel}"`;
  }

  return headers;
}
