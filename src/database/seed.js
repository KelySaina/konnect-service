const bcrypt = require("bcrypt");
const crypto = require("crypto");
const { sequelize, User, Role, Permission, OAuthClient } = require("../models");
const config = require("../config");

const PERMISSIONS = [
  { name: "users:create", resource: "users", action: "create" },
  { name: "users:read", resource: "users", action: "read" },
  { name: "users:update", resource: "users", action: "update" },
  { name: "users:delete", resource: "users", action: "delete" },
  { name: "roles:create", resource: "roles", action: "create" },
  { name: "roles:read", resource: "roles", action: "read" },
  { name: "roles:update", resource: "roles", action: "update" },
  { name: "roles:delete", resource: "roles", action: "delete" },
  { name: "clients:create", resource: "clients", action: "create" },
  { name: "clients:read", resource: "clients", action: "read" },
  { name: "clients:update", resource: "clients", action: "update" },
  { name: "clients:delete", resource: "clients", action: "delete" },
  { name: "permissions:read", resource: "permissions", action: "read" },
  { name: "permissions:manage", resource: "permissions", action: "manage" },
];

async function seed() {
  try {
    // Create permissions
    const perms = [];
    for (const p of PERMISSIONS) {
      const [perm] = await Permission.findOrCreate({ where: { name: p.name }, defaults: p });
      perms.push(perm);
    }
    console.log(`${perms.length} permissions ensured.`);

    // Create roles
    const [adminRole] = await Role.findOrCreate({
      where: { name: "admin" },
      defaults: { name: "admin", description: "Full system administrator", is_system: true },
    });
    await adminRole.setPermissions(perms);

    const [userRole] = await Role.findOrCreate({
      where: { name: "user" },
      defaults: { name: "user", description: "Standard user", is_system: true },
    });
    // Users can read their own profile — no admin perms
    console.log("Roles created: admin, user");

    // Create admin user
    const passwordHash = await bcrypt.hash(config.admin.password, 12);
    const [admin] = await User.findOrCreate({
      where: { email: config.admin.email },
      defaults: {
        email: config.admin.email,
        username: "admin",
        password_hash: passwordHash,
        first_name: "System",
        last_name: "Admin",
        email_verified: true,
        active: true,
      },
    });
    await admin.setRoles([adminRole]);
    console.log(`Admin user: ${config.admin.email}`);

    // Create a default OAuth client for the frontend
    const clientId = "konnect-webapp";
    const clientSecret = crypto.randomBytes(32).toString("hex");
    const [client] = await OAuthClient.findOrCreate({
      where: { client_id: clientId },
      defaults: {
        client_id: clientId,
        client_secret_hash: await bcrypt.hash(clientSecret, 10),
        name: "Konnect Web App",
        description: "Built-in web application",
        redirect_uris: [`${config.clientUrl}/callback`],
        allowed_scopes: ["openid", "profile", "email", "address", "phone", "offline_access"],
        grant_types: ["authorization_code", "refresh_token"],
        token_endpoint_auth_method: "none",
        is_confidential: false,
        active: true,
      },
    });
    console.log(`OAuth Client: ${clientId}`);
    console.log(`  Client Secret: ${clientSecret} (save this!)`);

    console.log("\nSeed completed successfully.");
  } catch (err) {
    console.error("Seed failed:", err.message);
    throw err;
  }
}

module.exports = { seed };

// Allow direct execution: node src/database/seed.js
if (require.main === module) {
  const { sequelize } = require("../models");
  seed()
    .then(() => sequelize.close())
    .catch(() => process.exit(1));
}
