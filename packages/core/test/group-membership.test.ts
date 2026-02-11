import { expect } from 'chai';
import { GroupRegistry } from '../src/group-membership';

describe('Group Membership', () => {
  let registry: GroupRegistry;

  beforeEach(() => {
    registry = new GroupRegistry();
  });

  describe('GroupRegistry - createGroup', () => {
    it('should create a group with valid parameters', () => {
      const group = registry.createGroup('students', 'Student Body', 'All enrolled students');

      expect(group.id).to.equal('students');
      expect(group.name).to.equal('Student Body');
      expect(group.description).to.equal('All enrolled students');
      expect(group.tree).to.exist;
    });

    it('should throw for duplicate group ID', () => {
      registry.createGroup('alumni', 'Alumni', 'Former students');

      expect(() => registry.createGroup('alumni', 'Alumni 2', 'Another group')).to.throw(
        /already exists/,
      );
    });

    it('should throw for empty group ID', () => {
      expect(() => registry.createGroup('', 'Name', 'Description')).to.throw(/non-empty string/);
    });

    it('should throw for empty group name', () => {
      expect(() => registry.createGroup('id', '', 'Description')).to.throw(/non-empty string/);
    });

    it('should use custom tree depth', () => {
      const group = registry.createGroup('small-group', 'Small', 'Small group', 5);

      expect(group.tree).to.exist;
      // Tree should accept the custom depth (will be validated by InMemoryValidCredentialTree)
    });
  });

  describe('GroupRegistry - addMember', () => {
    it('should add a member to a group', async () => {
      registry.createGroup('veterans', 'Veterans', 'Military veterans');
      const commitment = '123456789012345';

      await registry.addMember('veterans', commitment);
      const isMember = await registry.isMember('veterans', commitment);

      expect(isMember).to.be.true;
    });

    it('should throw when adding to non-existent group', async () => {
      try {
        await registry.addMember('unknown', '123');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/not found/);
      }
    });

    it('should be idempotent', async () => {
      registry.createGroup('employees', 'Employees', 'Company employees');
      const commitment = '987654321098765';

      await registry.addMember('employees', commitment);
      await registry.addMember('employees', commitment);

      const isMember = await registry.isMember('employees', commitment);
      expect(isMember).to.be.true;
    });
  });

  describe('GroupRegistry - removeMember', () => {
    it('should remove a member from a group', async () => {
      registry.createGroup('students', 'Students', 'Enrolled students');
      const commitment = '123456789';

      await registry.addMember('students', commitment);
      await registry.removeMember('students', commitment);

      const isMember = await registry.isMember('students', commitment);
      expect(isMember).to.be.false;
    });

    it('should throw when removing from non-existent group', async () => {
      try {
        await registry.removeMember('unknown', '123456789');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/not found/);
      }
    });

    it('should be idempotent', async () => {
      registry.createGroup('alumni', 'Alumni', 'Former students');
      const commitment = '123456789';

      await registry.addMember('alumni', commitment);
      await registry.removeMember('alumni', commitment);
      await registry.removeMember('alumni', commitment);

      const isMember = await registry.isMember('alumni', commitment);
      expect(isMember).to.be.false;
    });
  });

  describe('GroupRegistry - isMember', () => {
    it('should return true for group members', async () => {
      registry.createGroup('faculty', 'Faculty', 'Teaching staff');
      const commitment = '123456789';

      await registry.addMember('faculty', commitment);
      const isMember = await registry.isMember('faculty', commitment);

      expect(isMember).to.be.true;
    });

    it('should return false for non-members', async () => {
      registry.createGroup('admins', 'Admins', 'Administrators');
      const isMember = await registry.isMember('admins', '123456789');

      expect(isMember).to.be.false;
    });

    it('should throw for non-existent group', async () => {
      try {
        await registry.isMember('unknown', '123456789');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/not found/);
      }
    });
  });

  describe('GroupRegistry - getMembershipWitness', () => {
    it('should return a witness for group members', async () => {
      registry.createGroup('donors', 'Donors', 'Financial donors');
      const commitment = '123456789';

      await registry.addMember('donors', commitment);
      const witness = await registry.getMembershipWitness('donors', commitment);

      expect(witness).to.not.be.null;
      expect(witness).to.have.property('root');
      expect(witness).to.have.property('siblings');
      expect(witness).to.have.property('pathIndices');
    });

    it('should return null for non-members', async () => {
      registry.createGroup('members', 'Members', 'Regular members');
      const witness = await registry.getMembershipWitness('members', '123456789');

      expect(witness).to.be.null;
    });

    it('should throw for non-existent group', async () => {
      try {
        await registry.getMembershipWitness('unknown', '123456789');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/not found/);
      }
    });
  });

  describe('GroupRegistry - getGroupRoot', () => {
    it('should return a valid root', async () => {
      registry.createGroup('partners', 'Partners', 'Business partners');
      const root = await registry.getGroupRoot('partners');

      expect(root).to.be.a('string');
      expect(root.length).to.be.greaterThan(0);
    });

    it('should throw for non-existent group', async () => {
      try {
        await registry.getGroupRoot('unknown');
        expect.fail('Expected error to be thrown');
      } catch (error: any) {
        expect(error.message).to.match(/not found/);
      }
    });

    it('should change when members are added', async () => {
      registry.createGroup('volunteers', 'Volunteers', 'Community volunteers');
      const emptyRoot = await registry.getGroupRoot('volunteers');

      await registry.addMember('volunteers', '123456789');
      const updatedRoot = await registry.getGroupRoot('volunteers');

      expect(updatedRoot).to.not.equal(emptyRoot);
    });
  });

  describe('GroupRegistry - listGroups', () => {
    it('should return empty array initially', () => {
      const groups = registry.listGroups();
      expect(groups).to.be.an('array').with.lengthOf(0);
    });

    it('should list all created groups', () => {
      registry.createGroup('group1', 'Group 1', 'First group');
      registry.createGroup('group2', 'Group 2', 'Second group');

      const groups = registry.listGroups();

      expect(groups).to.have.lengthOf(2);
      expect(groups.map((g) => g.id)).to.include.members(['group1', 'group2']);
    });
  });

  describe('GroupRegistry - getGroup', () => {
    it('should return group by ID', () => {
      registry.createGroup('test-group', 'Test', 'Test group');
      const group = registry.getGroup('test-group');

      expect(group).to.exist;
      expect(group?.id).to.equal('test-group');
    });

    it('should return undefined for unknown ID', () => {
      const group = registry.getGroup('unknown');
      expect(group).to.be.undefined;
    });
  });

  describe('Witness round-trip', () => {
    it('should have root matching current group root', async () => {
      registry.createGroup('verified', 'Verified', 'Verified users');
      const commitment = '123456789';

      await registry.addMember('verified', commitment);
      const witness = await registry.getMembershipWitness('verified', commitment);
      const currentRoot = await registry.getGroupRoot('verified');

      expect(witness?.root).to.equal(currentRoot);
    });

    it('should have path length matching tree depth', async () => {
      const depth = 8;
      registry.createGroup('custom-depth', 'Custom', 'Custom depth group', depth);
      const commitment = '123456789';

      await registry.addMember('custom-depth', commitment);
      const witness = await registry.getMembershipWitness('custom-depth', commitment);

      expect(witness?.siblings).to.have.lengthOf(depth);
      expect(witness?.pathIndices).to.have.lengthOf(depth);
    });
  });

  describe('Lifecycle operations', () => {
    it('should handle add/remove/add cycle', async () => {
      registry.createGroup('cycle', 'Cycle', 'Cycle test group');
      const commitment = '123456789';

      await registry.addMember('cycle', commitment);
      expect(await registry.isMember('cycle', commitment)).to.be.true;

      await registry.removeMember('cycle', commitment);
      expect(await registry.isMember('cycle', commitment)).to.be.false;

      await registry.addMember('cycle', commitment);
      expect(await registry.isMember('cycle', commitment)).to.be.true;
    });

    it('should update root on membership changes', async () => {
      registry.createGroup('dynamic', 'Dynamic', 'Dynamic group');
      const root1 = await registry.getGroupRoot('dynamic');

      await registry.addMember('dynamic', '123456789');
      const root2 = await registry.getGroupRoot('dynamic');

      await registry.removeMember('dynamic', '123456789');
      const root3 = await registry.getGroupRoot('dynamic');

      expect(root2).to.not.equal(root1);
      expect(root3).to.not.equal(root2);
      expect(root3).to.equal(root1); // Back to empty state
    });

    it('should provide independent witnesses for multiple members', async () => {
      registry.createGroup('multi', 'Multi', 'Multiple members');
      const member1 = '123456789';
      const member2 = '987654321';

      await registry.addMember('multi', member1);
      await registry.addMember('multi', member2);

      const witness1 = await registry.getMembershipWitness('multi', member1);
      const witness2 = await registry.getMembershipWitness('multi', member2);

      expect(witness1).to.not.be.null;
      expect(witness2).to.not.be.null;
      expect(witness1?.root).to.equal(witness2?.root);
      // Siblings should differ for different members
      expect(witness1?.siblings).to.not.deep.equal(witness2?.siblings);
    });
  });

  describe('Edge cases', () => {
    it('should have valid root for empty group', async () => {
      registry.createGroup('empty', 'Empty', 'Empty group');
      const root = await registry.getGroupRoot('empty');

      expect(root).to.be.a('string');
      expect(root.length).to.be.greaterThan(0);
    });

    it('should handle duplicate add as idempotent', async () => {
      registry.createGroup('idem', 'Idempotent', 'Idempotent test');
      const commitment = '123456789';

      await registry.addMember('idem', commitment);
      const root1 = await registry.getGroupRoot('idem');

      await registry.addMember('idem', commitment);
      const root2 = await registry.getGroupRoot('idem');

      expect(root2).to.equal(root1);
    });
  });
});
