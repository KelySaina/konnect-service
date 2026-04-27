const { GraphQLError } = require("graphql");
const bcrypt = require("bcrypt");
const { Op } = require("sequelize");
const { User, Address, Role, Permission, OAuthClient, Organization } = require("../models");
const crypto = require("crypto");

// ---------- Helpers ----------

function requireAuth(ctx) {
  if (!ctx.user) {
    throw new GraphQLError("Not authenticated", {
      extensions: { code: "UNAUTHENTICATED" },
    });
  }
  return ctx.user;
}

function requireAdmin(ctx) {
  const user = requireAuth(ctx);
  const isAdmin = user.roles && user.roles.some((r) => r.name === "admin");
  if (!isAdmin) {
    throw new GraphQLError("Forbidden", {
      extensions: { code: "FORBIDDEN" },
    });
  }
  return user;
}

// ---------- Resolvers ----------

const resolvers = {
  // Scalar handling
  DateTime: {
    __serialize(value) {
      return value instanceof Date ? value.toISOString() : value;
    },
  },
  JSON: {
    __serialize(value) {
      return value;
    },
  },

  // Field resolvers
  User: {
    avatar_url: (parent) => {
      if (!parent.avatar_url) return null;
      // If already a full URL (legacy), return as-is
      if (parent.avatar_url.startsWith("http")) return parent.avatar_url;
      // Otherwise it's a storage key — return the API proxy path
      return `/api/files/${parent.avatar_url}`;
    },
    addresses: (parent) =>
      parent.addresses || Address.findAll({ where: { user_id: parent.id } }),
    roles: (parent) =>
      parent.roles || parent.getRoles({ include: [{ model: Permission, as: "permissions" }] }),
    organizations: (parent) =>
      parent.organizations || parent.getOrganizations(),
  },
  Role: {
    permissions: (parent) =>
      parent.permissions || parent.getPermissions(),
  },
  Organization: {
    members: (parent) =>
      parent.members || parent.getMembers(),
  },

  // ---------- Queries ----------
  Query: {
    me: async (_parent, _args, ctx) => {
      const user = requireAuth(ctx);
      return User.findByPk(user.id, {
        include: [
          { model: Address, as: "addresses" },
          { model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] },
        ],
      });
    },

    user: async (_parent, { id }, ctx) => {
      requireAdmin(ctx);
      return User.findByPk(id, {
        include: [
          { model: Address, as: "addresses" },
          { model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] },
        ],
      });
    },

    users: async (_parent, { page = 1, pageSize = 20, filter = {} }, ctx) => {
      requireAdmin(ctx);
      const where = {};
      if (filter.active !== undefined) where.active = filter.active;
      if (filter.email_verified !== undefined) where.email_verified = filter.email_verified;
      if (filter.search) {
        where[Op.or] = [
          { email: { [Op.iLike]: `%${filter.search}%` } },
          { username: { [Op.iLike]: `%${filter.search}%` } },
          { first_name: { [Op.iLike]: `%${filter.search}%` } },
          { last_name: { [Op.iLike]: `%${filter.search}%` } },
        ];
      }

      const include = [
        { model: Address, as: "addresses" },
        { model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] },
      ];

      // Filter by role name
      if (filter.role) {
        include[1].where = { name: filter.role };
      }

      const { rows, count } = await User.findAndCountAll({
        where,
        include,
        limit: Math.min(pageSize, 100),
        offset: (page - 1) * pageSize,
        order: [["createdAt", "DESC"]],
        distinct: true,
      });
      return { rows, count, page, pageSize };
    },

    role: async (_parent, { id }, ctx) => {
      requireAuth(ctx);
      return Role.findByPk(id, { include: [{ model: Permission, as: "permissions" }] });
    },

    roles: async (_parent, _args, ctx) => {
      requireAuth(ctx);
      return Role.findAll({ include: [{ model: Permission, as: "permissions" }] });
    },

    permissions: async (_parent, _args, ctx) => {
      requireAuth(ctx);
      return Permission.findAll();
    },

    client: async (_parent, { id }, ctx) => {
      requireAdmin(ctx);
      return OAuthClient.findByPk(id);
    },

    clients: async (_parent, { page = 1, pageSize = 20 }, ctx) => {
      requireAdmin(ctx);
      const { rows, count } = await OAuthClient.findAndCountAll({
        limit: Math.min(pageSize, 100),
        offset: (page - 1) * pageSize,
        order: [["createdAt", "DESC"]],
      });
      return { rows, count, page, pageSize };
    },

    organization: async (_parent, { id }, ctx) => {
      requireAuth(ctx);
      return Organization.findByPk(id, { include: [{ model: User, as: "members" }] });
    },

    organizations: async (_parent, { page = 1, pageSize = 20 }, ctx) => {
      requireAdmin(ctx);
      const { rows, count } = await Organization.findAndCountAll({
        include: [{ model: User, as: "members" }],
        limit: Math.min(pageSize, 100),
        offset: (page - 1) * pageSize,
        order: [["createdAt", "DESC"]],
        distinct: true,
      });
      return { rows, count, page, pageSize };
    },
  },

  // ---------- Mutations ----------
  Mutation: {
    createUser: async (_parent, { input }, ctx) => {
      requireAdmin(ctx);
      const password_hash = await bcrypt.hash(input.password, 12);
      const { password, ...rest } = input;
      return User.create({ ...rest, password_hash });
    },

    updateUser: async (_parent, { id, input }, ctx) => {
      const currentUser = requireAuth(ctx);
      const isAdmin = currentUser.roles && currentUser.roles.some((r) => r.name === "admin");
      if (currentUser.id !== id && !isAdmin) {
        throw new GraphQLError("Forbidden", { extensions: { code: "FORBIDDEN" } });
      }
      const user = await User.findByPk(id);
      if (!user) throw new GraphQLError("User not found");
      await user.update(input);
      return user.reload({
        include: [
          { model: Address, as: "addresses" },
          { model: Role, as: "roles" },
        ],
      });
    },

    deactivateUser: async (_parent, { id }, ctx) => {
      requireAdmin(ctx);
      const user = await User.findByPk(id);
      if (!user) throw new GraphQLError("User not found");
      await user.update({ active: false });
      return user;
    },

    addAddress: async (_parent, { userId, input }, ctx) => {
      const currentUser = requireAuth(ctx);
      const isAdmin = currentUser.roles && currentUser.roles.some((r) => r.name === "admin");
      if (currentUser.id !== userId && !isAdmin) {
        throw new GraphQLError("Forbidden", { extensions: { code: "FORBIDDEN" } });
      }
      return Address.create({ ...input, user_id: userId });
    },

    removeAddress: async (_parent, { id }, ctx) => {
      const currentUser = requireAuth(ctx);
      const address = await Address.findByPk(id);
      if (!address) throw new GraphQLError("Address not found");
      const isAdmin = currentUser.roles && currentUser.roles.some((r) => r.name === "admin");
      if (address.user_id !== currentUser.id && !isAdmin) {
        throw new GraphQLError("Forbidden", { extensions: { code: "FORBIDDEN" } });
      }
      await address.destroy();
      return true;
    },

    assignRole: async (_parent, { userId, roleId }, ctx) => {
      requireAdmin(ctx);
      const user = await User.findByPk(userId);
      const role = await Role.findByPk(roleId);
      if (!user || !role) throw new GraphQLError("User or Role not found");
      await user.addRole(role);
      return user.reload({ include: [{ model: Role, as: "roles" }] });
    },

    revokeRole: async (_parent, { userId, roleId }, ctx) => {
      requireAdmin(ctx);
      const user = await User.findByPk(userId);
      const role = await Role.findByPk(roleId);
      if (!user || !role) throw new GraphQLError("User or Role not found");
      await user.removeRole(role);
      return user.reload({ include: [{ model: Role, as: "roles" }] });
    },

    createRole: async (_parent, { input }, ctx) => {
      requireAdmin(ctx);
      return Role.create(input);
    },

    deleteRole: async (_parent, { id }, ctx) => {
      requireAdmin(ctx);
      const role = await Role.findByPk(id);
      if (!role) throw new GraphQLError("Role not found");
      if (role.is_system) {
        throw new GraphQLError("Cannot delete system role", {
          extensions: { code: "BAD_USER_INPUT" },
        });
      }
      await role.destroy();
      return true;
    },

    updateRole: async (_parent, { id, input }, ctx) => {
      requireAdmin(ctx);
      const role = await Role.findByPk(id);
      if (!role) throw new GraphQLError("Role not found");
      await role.update(input);
      return role.reload({ include: [{ model: Permission, as: "permissions" }] });
    },

    assignPermission: async (_parent, { roleId, permissionId }, ctx) => {
      requireAdmin(ctx);
      const role = await Role.findByPk(roleId);
      const perm = await Permission.findByPk(permissionId);
      if (!role || !perm) throw new GraphQLError("Role or Permission not found");
      await role.addPermission(perm);
      return role.reload({ include: [{ model: Permission, as: "permissions" }] });
    },

    revokePermission: async (_parent, { roleId, permissionId }, ctx) => {
      requireAdmin(ctx);
      const role = await Role.findByPk(roleId);
      const perm = await Permission.findByPk(permissionId);
      if (!role || !perm) throw new GraphQLError("Role or Permission not found");
      await role.removePermission(perm);
      return role.reload({ include: [{ model: Permission, as: "permissions" }] });
    },

    createClient: async (_parent, { input }, ctx) => {
      requireAdmin(ctx);
      const client_id = `konnect_${crypto.randomBytes(16).toString("hex")}`;
      const client_secret = crypto.randomBytes(32).toString("hex");
      const client_secret_hash = input.is_confidential !== false
        ? await bcrypt.hash(client_secret, 10)
        : null;

      const client = await OAuthClient.create({
        ...input,
        client_id,
        client_secret_hash,
        is_confidential: input.is_confidential !== false,
      });

      // Return the plain secret only on creation (won't be retrievable later)
      const result = client.toJSON();
      result._client_secret = client_secret;
      return result;
    },

    updateClient: async (_parent, { id, input }, ctx) => {
      requireAdmin(ctx);
      const client = await OAuthClient.findByPk(id);
      if (!client) throw new GraphQLError("Client not found");
      await client.update(input);
      return client;
    },

    revokeClient: async (_parent, { id }, ctx) => {
      requireAdmin(ctx);
      const client = await OAuthClient.findByPk(id);
      if (!client) throw new GraphQLError("Client not found");
      await client.update({ active: false });
      return client;
    },

    createOrganization: async (_parent, { input }, ctx) => {
      requireAdmin(ctx);
      return Organization.create(input);
    },

    updateOrganization: async (_parent, { id, input }, ctx) => {
      requireAdmin(ctx);
      const org = await Organization.findByPk(id);
      if (!org) throw new GraphQLError("Organization not found");
      await org.update(input);
      return org;
    },

    addOrganizationMember: async (_parent, { organizationId, userId }, ctx) => {
      requireAdmin(ctx);
      const org = await Organization.findByPk(organizationId);
      const user = await User.findByPk(userId);
      if (!org || !user) throw new GraphQLError("Organization or User not found");
      await org.addMember(user);
      return org.reload({ include: [{ model: User, as: "members" }] });
    },

    removeOrganizationMember: async (_parent, { organizationId, userId }, ctx) => {
      requireAdmin(ctx);
      const org = await Organization.findByPk(organizationId);
      const user = await User.findByPk(userId);
      if (!org || !user) throw new GraphQLError("Organization or User not found");
      await org.removeMember(user);
      return org.reload({ include: [{ model: User, as: "members" }] });
    },
  },
};

module.exports = resolvers;
