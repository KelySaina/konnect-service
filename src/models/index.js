const sequelize = require("../config/database");
const User = require("./User");
const Address = require("./Address");
const Role = require("./Role");
const Permission = require("./Permission");
const Organization = require("./Organization");
const OAuthClient = require("./OAuthClient");
const AuthorizationCode = require("./AuthorizationCode");
const RefreshToken = require("./RefreshToken");

// User <-> Address
User.hasMany(Address, { foreignKey: "user_id", as: "addresses" });
Address.belongsTo(User, { foreignKey: "user_id" });

// User <-> Role (many-to-many)
User.belongsToMany(Role, { through: "user_roles", foreignKey: "user_id", as: "roles" });
Role.belongsToMany(User, { through: "user_roles", foreignKey: "role_id", as: "users" });

// Role <-> Permission (many-to-many)
Role.belongsToMany(Permission, { through: "role_permissions", foreignKey: "role_id", as: "permissions" });
Permission.belongsToMany(Role, { through: "role_permissions", foreignKey: "permission_id", as: "roles" });

// Organization <-> User (many-to-many)
Organization.belongsToMany(User, { through: "organization_members", foreignKey: "organization_id", as: "members" });
User.belongsToMany(Organization, { through: "organization_members", foreignKey: "user_id", as: "organizations" });

// AuthorizationCode -> User, OAuthClient
AuthorizationCode.belongsTo(User, { foreignKey: "user_id" });
AuthorizationCode.belongsTo(OAuthClient, { foreignKey: "client_id" });

// RefreshToken -> User
RefreshToken.belongsTo(User, { foreignKey: "user_id" });

module.exports = {
  sequelize,
  User,
  Address,
  Role,
  Permission,
  Organization,
  OAuthClient,
  AuthorizationCode,
  RefreshToken,
};
