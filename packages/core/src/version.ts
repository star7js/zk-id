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
