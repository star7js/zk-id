import { expect } from 'chai';
import {
  RedisTreeSyncChannel,
  SyncedValidCredentialTree,
  TreeSyncEvent,
  RedisPubClient,
  RedisSubClient,
} from '../src/tree-sync';
import { ValidCredentialTree, RevocationWitness, RevocationRootInfo } from '@zk-id/core';

// ---------------------------------------------------------------------------
// Minimal in-process pub/sub mock (no Redis needed)
// ---------------------------------------------------------------------------

class MockPubSub {
  private listeners: Map<string, ((channel: string, message: string) => void)[]> = new Map();

  createPubClient(): RedisPubClient {
    return {
      publish: async (channel: string, message: string): Promise<number> => {
        const handlers = this.listeners.get(channel) ?? [];
        for (const handler of handlers) {
          handler(channel, message);
        }
        return handlers.length;
      },
    };
  }

  createSubClient(): RedisSubClient {
    const self = this;
    const handlers: ((channel: string, message: string) => void)[] = [];
    let subscribedChannels: string[] = [];

    return {
      async subscribe(...channels: string[]): Promise<unknown> {
        for (const ch of channels) {
          subscribedChannels.push(ch);
          if (!self.listeners.has(ch)) {
            self.listeners.set(ch, []);
          }
          for (const handler of handlers) {
            self.listeners.get(ch)!.push(handler);
          }
        }
        return channels.length;
      },
      async unsubscribe(...channels: string[]): Promise<unknown> {
        for (const ch of channels) {
          self.listeners.delete(ch);
          subscribedChannels = subscribedChannels.filter((c) => c !== ch);
        }
        return channels.length;
      },
      on(event: string, handler: (channel: string, message: string) => void) {
        if (event === 'message') {
          handlers.push(handler);
          // Also register for already-subscribed channels
          for (const ch of subscribedChannels) {
            self.listeners.get(ch)?.push(handler);
          }
        }
        return this as any;
      },
      removeAllListeners(_event?: string) {
        handlers.length = 0;
        for (const ch of subscribedChannels) {
          self.listeners.set(ch, []);
        }
        return this as any;
      },
    };
  }
}

// ---------------------------------------------------------------------------
// Stub tree (tracks calls, does not do real Poseidon hashing)
// ---------------------------------------------------------------------------

class StubValidCredentialTree implements ValidCredentialTree {
  private commitments = new Set<string>();
  private version = 0;
  private updatedAt = new Date().toISOString();
  addCalls: string[] = [];
  removeCalls: string[] = [];

  async add(commitment: string): Promise<void> {
    this.addCalls.push(commitment);
    this.commitments.add(commitment);
    this.version++;
    this.updatedAt = new Date().toISOString();
  }

  async remove(commitment: string): Promise<void> {
    this.removeCalls.push(commitment);
    this.commitments.delete(commitment);
    this.version++;
    this.updatedAt = new Date().toISOString();
  }

  async contains(commitment: string): Promise<boolean> {
    return this.commitments.has(commitment);
  }

  async getRoot(): Promise<string> {
    return `root-v${this.version}`;
  }

  async getRootInfo(): Promise<RevocationRootInfo> {
    return {
      root: `root-v${this.version}`,
      version: this.version,
      updatedAt: this.updatedAt,
    };
  }

  async getWitness(commitment: string): Promise<RevocationWitness | null> {
    if (!this.commitments.has(commitment)) return null;
    return { root: `root-v${this.version}`, pathIndices: [0], siblings: ['0'] };
  }

  async size(): Promise<number> {
    return this.commitments.size;
  }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

describe('RedisTreeSyncChannel', () => {
  it('publishes and receives events', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    const received: TreeSyncEvent[] = [];
    channel.onUpdate((event) => received.push(event));
    await channel.start();

    const event: TreeSyncEvent = {
      root: 'abc',
      version: 1,
      updatedAt: new Date().toISOString(),
      source: 'node-1',
    };
    await channel.publish(event);

    expect(received).to.have.length(1);
    expect(received[0].root).to.equal('abc');
    expect(received[0].source).to.equal('node-1');

    await channel.close();
  });

  it('supports multiple handlers', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    let countA = 0;
    let countB = 0;
    channel.onUpdate(() => countA++);
    channel.onUpdate(() => countB++);
    await channel.start();

    await channel.publish({
      root: 'x',
      version: 1,
      updatedAt: new Date().toISOString(),
      source: 'n',
    });

    expect(countA).to.equal(1);
    expect(countB).to.equal(1);

    await channel.close();
  });

  it('uses custom channel name', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
      { channel: 'custom:channel' },
    );

    const received: TreeSyncEvent[] = [];
    channel.onUpdate((event) => received.push(event));
    await channel.start();

    await channel.publish({
      root: 'y',
      version: 1,
      updatedAt: new Date().toISOString(),
      source: 'n',
    });

    expect(received).to.have.length(1);

    await channel.close();
  });

  it('ignores malformed messages', async () => {
    const pubsub = new MockPubSub();
    const pub = pubsub.createPubClient();
    const channel = new RedisTreeSyncChannel(pub, pubsub.createSubClient());

    const received: TreeSyncEvent[] = [];
    channel.onUpdate((event) => received.push(event));
    await channel.start();

    // Publish raw invalid JSON directly
    await pub.publish('zkid:tree:sync', 'not-json');

    expect(received).to.have.length(0);

    await channel.close();
  });

  it('stops receiving after close()', async () => {
    const pubsub = new MockPubSub();
    const pub = pubsub.createPubClient();
    const channel = new RedisTreeSyncChannel(pub, pubsub.createSubClient());

    const received: TreeSyncEvent[] = [];
    channel.onUpdate((event) => received.push(event));
    await channel.start();
    await channel.close();

    await pub.publish(
      'zkid:tree:sync',
      JSON.stringify({ root: 'z', version: 1, updatedAt: '', source: 'n' }),
    );

    expect(received).to.have.length(0);
  });

  it('start() is idempotent', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    await channel.start();
    await channel.start(); // should not throw or double-subscribe

    await channel.close();
  });
});

describe('SyncedValidCredentialTree', () => {
  it('delegates add/remove to inner tree', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channel.start();

    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel, { nodeId: 'node-A' });

    await synced.add('commit-1');
    await synced.remove('commit-1');

    expect(inner.addCalls).to.deep.equal(['commit-1']);
    expect(inner.removeCalls).to.deep.equal(['commit-1']);

    await channel.close();
  });

  it('broadcasts sync events on add/remove', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    const published: TreeSyncEvent[] = [];
    channel.onUpdate((event) => published.push(event));
    await channel.start();

    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel, { nodeId: 'node-A' });

    await synced.add('commit-1');
    await synced.add('commit-2');
    await synced.remove('commit-1');

    expect(published).to.have.length(3);
    expect(published[0].source).to.equal('node-A');
    expect(published[0].version).to.equal(1);
    expect(published[1].version).to.equal(2);
    expect(published[2].version).to.equal(3);

    await channel.close();
  });

  it('ignores self-notifications', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channel.start();

    const remoteUpdates: TreeSyncEvent[] = [];
    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel, {
      nodeId: 'node-A',
      onRemoteUpdate: (event) => { remoteUpdates.push(event); },
    });

    // This add will broadcast with source=node-A, which should be ignored
    await synced.add('commit-1');

    expect(remoteUpdates).to.have.length(0);

    await channel.close();
  });

  it('notifies on remote updates from other nodes', async () => {
    const pubsub = new MockPubSub();

    // Node A's channel
    const channelA = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channelA.start();

    // Node B's channel (same pub/sub bus)
    const channelB = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channelB.start();

    const remoteUpdatesA: TreeSyncEvent[] = [];
    const remoteUpdatesB: TreeSyncEvent[] = [];

    const treeA = new StubValidCredentialTree();
    const syncedA = new SyncedValidCredentialTree(treeA, channelA, {
      nodeId: 'node-A',
      onRemoteUpdate: (event) => { remoteUpdatesA.push(event); },
    });

    const treeB = new StubValidCredentialTree();
    const syncedB = new SyncedValidCredentialTree(treeB, channelB, {
      nodeId: 'node-B',
      onRemoteUpdate: (event) => { remoteUpdatesB.push(event); },
    });

    // Node A adds a credential
    await syncedA.add('commit-1');

    // Node A should NOT get a remote update (self-notification ignored)
    expect(remoteUpdatesA).to.have.length(0);
    // Node B SHOULD get a remote update
    expect(remoteUpdatesB).to.have.length(1);
    expect(remoteUpdatesB[0].source).to.equal('node-A');

    // Node B adds a credential
    await syncedB.add('commit-2');

    // Now node A should get one
    expect(remoteUpdatesA).to.have.length(1);
    expect(remoteUpdatesA[0].source).to.equal('node-B');
    // Node B should still have only 1 (self-notification ignored)
    expect(remoteUpdatesB).to.have.length(1);

    await channelA.close();
    await channelB.close();
  });

  it('tracks last known remote version', async () => {
    const pubsub = new MockPubSub();
    const channelA = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    const channelB = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channelA.start();
    await channelB.start();

    const treeA = new StubValidCredentialTree();
    const syncedA = new SyncedValidCredentialTree(treeA, channelA, { nodeId: 'A' });

    const treeB = new StubValidCredentialTree();
    const syncedB = new SyncedValidCredentialTree(treeB, channelB, { nodeId: 'B' });

    expect(syncedB.getLastKnownRemoteVersion()).to.equal(-1);

    await syncedA.add('c1');
    expect(syncedB.getLastKnownRemoteVersion()).to.equal(1);

    await syncedA.add('c2');
    expect(syncedB.getLastKnownRemoteVersion()).to.equal(2);

    await channelA.close();
    await channelB.close();
  });

  it('delegates read operations to inner tree', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channel.start();

    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel, { nodeId: 'n' });

    await synced.add('commit-1');
    await synced.add('commit-2');

    expect(await synced.contains('commit-1')).to.be.true;
    expect(await synced.contains('nonexistent')).to.be.false;
    expect(await synced.size()).to.equal(2);
    expect(await synced.getRoot()).to.equal('root-v2');

    const rootInfo = await synced.getRootInfo();
    expect(rootInfo.version).to.equal(2);

    const witness = await synced.getWitness('commit-1');
    expect(witness).to.not.be.null;
    expect(witness!.root).to.equal('root-v2');

    await channel.close();
  });

  it('exposes nodeId', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel, { nodeId: 'my-node' });

    expect(synced.getNodeId()).to.equal('my-node');

    await channel.close();
  });

  it('generates a random nodeId when not provided', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );

    const inner = new StubValidCredentialTree();
    const synced = new SyncedValidCredentialTree(inner, channel);

    expect(synced.getNodeId()).to.be.a('string');
    expect(synced.getNodeId().length).to.be.greaterThan(0);

    await channel.close();
  });

  it('handles getRootInfo fallback when inner tree lacks getRootInfo', async () => {
    const pubsub = new MockPubSub();
    const channel = new RedisTreeSyncChannel(
      pubsub.createPubClient(),
      pubsub.createSubClient(),
    );
    await channel.start();

    // Create a minimal tree without getRootInfo
    const minimalTree: ValidCredentialTree = {
      add: async () => {},
      remove: async () => {},
      contains: async () => false,
      getRoot: async () => 'minimal-root',
      getWitness: async () => null,
      size: async () => 0,
    };

    const synced = new SyncedValidCredentialTree(minimalTree, channel, { nodeId: 'n' });

    const info = await synced.getRootInfo();
    expect(info.root).to.equal('minimal-root');
    expect(info.version).to.equal(0);

    await channel.close();
  });
});
