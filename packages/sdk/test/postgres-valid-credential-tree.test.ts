import { expect } from 'chai';
import { PostgresValidCredentialTree } from '../src/postgres-valid-credential-tree';

const PG_URL =
  process.env.ZKID_PG_URL || process.env.POSTGRES_URL || process.env.PG_URL;

describe('PostgresValidCredentialTree', function () {
  if (!PG_URL) {
    it.skip('requires ZKID_PG_URL, POSTGRES_URL, or PG_URL to run', () => {});
    return;
  }

  // Load pg only when running integration tests.
  let PgClient: any;
  try {
    PgClient = require('pg').Client;
  } catch {
    it.skip('requires pg package to run integration tests', () => {});
    return;
  }

  this.timeout(20000);

  let client: any;
  const schema = `zkid_test_${Date.now()}`;

  before(async () => {
    client = new PgClient({ connectionString: PG_URL });
    await client.connect();
    await client.query(`CREATE SCHEMA ${schema};`);
  });

  after(async () => {
    await client.query(`DROP SCHEMA ${schema} CASCADE;`);
    await client.end();
  });

  it('stores commitments and returns root info', async () => {
    const tree = new PostgresValidCredentialTree(client, {
      depth: 3,
      schema,
      autoInit: true,
    });

    await tree.add('123');
    await tree.add('456');

    expect(await tree.contains('123')).to.equal(true);
    expect(await tree.contains('456')).to.equal(true);
    expect(await tree.size()).to.equal(2);

    const info = await tree.getRootInfo();
    expect(info.root).to.be.a('string');
    expect(info.version).to.equal(2);

    const witness = await tree.getWitness('123');
    expect(witness).to.not.equal(null);
    expect(witness?.siblings.length).to.equal(3);
  });

  it('reuses inactive indices and increments version', async () => {
    const tree = new PostgresValidCredentialTree(client, {
      depth: 3,
      schema,
      autoInit: true,
    });

    const info0 = await tree.getRootInfo();
    await tree.remove('123');
    const info1 = await tree.getRootInfo();
    expect(info1.version).to.equal(info0.version + 1);

    await tree.add('789');
    const info2 = await tree.getRootInfo();
    expect(info2.version).to.equal(info1.version + 1);
    expect(await tree.contains('789')).to.equal(true);
  });
});
