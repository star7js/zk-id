import { ValidCredentialTree, RevocationRootInfo, RevocationWitness } from '@zk-id/core';

// ---------------------------------------------------------------------------
// Pub/Sub client interfaces (compatible with ioredis)
// ---------------------------------------------------------------------------

/**
 * Minimal interface for a Redis client that can publish messages.
 * In ioredis, any client instance can publish.
 */
export interface RedisPubClient {
  publish(channel: string, message: string): Promise<number>;
}

/**
 * Minimal interface for a Redis client in subscriber mode.
 * In ioredis, a dedicated client is required for subscriptions
 * (it enters subscriber mode and can no longer issue normal commands).
 */
export interface RedisSubClient {
  subscribe(...channels: string[]): Promise<unknown>;
  unsubscribe(...channels: string[]): Promise<unknown>;
  on(event: 'message', handler: (channel: string, message: string) => void): this;
  removeAllListeners(event?: string): this;
}

// ---------------------------------------------------------------------------
// Sync event
// ---------------------------------------------------------------------------

/** Payload broadcast on every tree mutation. */
export interface TreeSyncEvent {
  /** Updated Merkle root */
  root: string;
  /** Monotonic root version */
  version: number;
  /** ISO 8601 timestamp of the mutation */
  updatedAt: string;
  /** Identifier of the node that performed the mutation */
  source: string;
}

// ---------------------------------------------------------------------------
// RedisTreeSyncChannel
// ---------------------------------------------------------------------------

export interface RedisTreeSyncChannelOptions {
  /** Redis pub/sub channel name (default: "zkid:tree:sync") */
  channel?: string;
}

export type TreeSyncHandler = (event: TreeSyncEvent) => void;

/**
 * Redis pub/sub channel for broadcasting tree mutation events.
 *
 * Usage:
 * ```ts
 * const pub = new Redis();   // normal client for publishing
 * const sub = new Redis();   // dedicated client for subscribing
 * const channel = new RedisTreeSyncChannel(pub, sub);
 * channel.onUpdate((event) => console.log('remote root changed', event));
 * await channel.start();
 * // ... later
 * await channel.close();
 * ```
 */
export class RedisTreeSyncChannel {
  private readonly pubClient: RedisPubClient;
  private readonly subClient: RedisSubClient;
  private readonly channel: string;
  private handlers: TreeSyncHandler[] = [];
  private started = false;

  private readonly messageHandler = (_ch: string, raw: string) => {
    let event: TreeSyncEvent;
    try {
      event = JSON.parse(raw) as TreeSyncEvent;
    } catch {
      return; // ignore malformed messages
    }
    for (const handler of this.handlers) {
      handler(event);
    }
  };

  constructor(
    pubClient: RedisPubClient,
    subClient: RedisSubClient,
    options: RedisTreeSyncChannelOptions = {},
  ) {
    this.pubClient = pubClient;
    this.subClient = subClient;
    this.channel = options.channel ?? 'zkid:tree:sync';
  }

  /** Register a handler for incoming sync events. */
  onUpdate(handler: TreeSyncHandler): void {
    this.handlers.push(handler);
  }

  /** Start listening for sync events (subscribes to the Redis channel). */
  async start(): Promise<void> {
    if (this.started) return;
    this.subClient.on('message', this.messageHandler);
    await this.subClient.subscribe(this.channel);
    this.started = true;
  }

  /** Publish a sync event to all listening nodes. */
  async publish(event: TreeSyncEvent): Promise<void> {
    await this.pubClient.publish(this.channel, JSON.stringify(event));
  }

  /** Stop listening and clean up. */
  async close(): Promise<void> {
    if (!this.started) return;
    await this.subClient.unsubscribe(this.channel);
    this.subClient.removeAllListeners('message');
    this.handlers = [];
    this.started = false;
  }
}

// ---------------------------------------------------------------------------
// SyncedValidCredentialTree
// ---------------------------------------------------------------------------

export interface SyncedValidCredentialTreeOptions {
  /**
   * Unique identifier for this node. Used to deduplicate self-notifications.
   * Defaults to a random hex string.
   */
  nodeId?: string;
  /**
   * Callback invoked when a remote node mutates the tree.
   * The local tree must be refreshed externally (e.g., Postgres tree
   * already detects version drift on next read; in-memory trees need
   * an explicit reload).
   */
  onRemoteUpdate?: (event: TreeSyncEvent) => void | Promise<void>;
}

/**
 * Wraps any `ValidCredentialTree` to broadcast mutations over a
 * `RedisTreeSyncChannel` and notify local listeners of remote changes.
 *
 * On `add()` / `remove()`, the wrapper:
 *   1. Delegates to the inner tree.
 *   2. Publishes a `TreeSyncEvent` with the new root + version.
 *
 * On receiving a remote event (different `nodeId`):
 *   1. Invokes the `onRemoteUpdate` callback so the consumer can
 *      invalidate caches or reload state.
 *
 * This is intentionally thin: the wrapper does NOT attempt to replay
 * remote mutations locally. Instead it signals staleness and relies
 * on the underlying tree implementation (e.g., `PostgresValidCredentialTree`
 * with version-based cache invalidation) to converge on next access.
 */
export class SyncedValidCredentialTree implements ValidCredentialTree {
  private readonly inner: ValidCredentialTree;
  private readonly syncChannel: RedisTreeSyncChannel;
  private readonly nodeId: string;
  private readonly onRemoteUpdate?: (event: TreeSyncEvent) => void | Promise<void>;
  private lastKnownVersion = -1;

  constructor(
    tree: ValidCredentialTree,
    syncChannel: RedisTreeSyncChannel,
    options: SyncedValidCredentialTreeOptions = {},
  ) {
    this.inner = tree;
    this.syncChannel = syncChannel;
    this.nodeId = options.nodeId ?? randomHex(8);
    this.onRemoteUpdate = options.onRemoteUpdate;

    // Listen for remote updates
    this.syncChannel.onUpdate((event) => {
      if (event.source === this.nodeId) return; // ignore own events
      this.lastKnownVersion = event.version;
      if (this.onRemoteUpdate) {
        this.onRemoteUpdate(event);
      }
    });
  }

  async add(commitment: string): Promise<void> {
    await this.inner.add(commitment);
    await this.broadcastCurrentState();
  }

  async remove(commitment: string): Promise<void> {
    await this.inner.remove(commitment);
    await this.broadcastCurrentState();
  }

  async contains(commitment: string): Promise<boolean> {
    return this.inner.contains(commitment);
  }

  async getRoot(): Promise<string> {
    return this.inner.getRoot();
  }

  async getRootInfo(): Promise<RevocationRootInfo> {
    if (this.inner.getRootInfo) {
      return this.inner.getRootInfo();
    }
    const root = await this.inner.getRoot();
    return { root, version: 0, updatedAt: new Date().toISOString() };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    return this.inner.getWitness(commitment);
  }

  async size(): Promise<number> {
    return this.inner.size();
  }

  /** The last version observed from a remote sync event (-1 if none). */
  getLastKnownRemoteVersion(): number {
    return this.lastKnownVersion;
  }

  /** The node identifier for this instance. */
  getNodeId(): string {
    return this.nodeId;
  }

  private async broadcastCurrentState(): Promise<void> {
    const info = await this.getRootInfo();
    await this.syncChannel.publish({
      root: info.root,
      version: info.version,
      updatedAt: info.updatedAt,
      source: this.nodeId,
    });
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function randomHex(bytes: number): string {
  const arr = new Uint8Array(bytes);
  // Works in both Node.js (globalThis.crypto) and browsers
  if (typeof globalThis !== 'undefined' && globalThis.crypto && globalThis.crypto.getRandomValues) {
    globalThis.crypto.getRandomValues(arr);
  } else {
    // Fallback for older Node.js without webcrypto
    for (let i = 0; i < bytes; i++) {
      arr[i] = Math.floor(Math.random() * 256);
    }
  }
  return Array.from(arr, (b) => b.toString(16).padStart(2, '0')).join('');
}
