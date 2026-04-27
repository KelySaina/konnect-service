const tokenService = require("../services/tokenService");
const { User, Role, Permission } = require("../models");

/**
 * Authenticate request via Bearer token.
 * Populates req.user with full user + roles.
 */
async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({ error: "unauthorized", message: "Missing or invalid token" });
  }

  try {
    const decoded = tokenService.verifyToken(authHeader.slice(7));
    const user = await User.findByPk(decoded.sub, {
      include: [{ model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] }],
    });

    if (!user || !user.active) {
      return res.status(401).json({ error: "unauthorized", message: "User not found or inactive" });
    }

    req.user = user;
    req.tokenScopes = (decoded.scope || "").split(" ");
    next();
  } catch (err) {
    return res.status(401).json({ error: "unauthorized", message: "Token expired or invalid" });
  }
}

/**
 * Require specific roles.
 * Usage: requireRole("admin") or requireRole("admin", "manager")
 */
function requireRole(...roles) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "unauthorized" });
    }
    const userRoles = req.user.roles ? req.user.roles.map((r) => r.name) : [];
    const hasRole = roles.some((r) => userRoles.includes(r));
    if (!hasRole) {
      return res.status(403).json({ error: "forbidden", message: `Requires role: ${roles.join(" or ")}` });
    }
    next();
  };
}

/**
 * Require specific permissions.
 * Usage: requirePermission("users:create") or requirePermission("users:read", "users:update")
 */
function requirePermission(...permissions) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ error: "unauthorized" });
    }
    const userPerms = new Set();
    if (req.user.roles) {
      for (const role of req.user.roles) {
        if (role.permissions) {
          for (const p of role.permissions) {
            userPerms.add(p.name);
          }
        }
      }
    }
    const hasPerm = permissions.some((p) => userPerms.has(p));
    if (!hasPerm) {
      return res.status(403).json({ error: "forbidden", message: `Requires permission: ${permissions.join(" or ")}` });
    }
    next();
  };
}

/**
 * Optional auth — attaches user if token valid, but doesn't reject.
 */
async function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return next();
  }
  try {
    const decoded = tokenService.verifyToken(authHeader.slice(7));
    const user = await User.findByPk(decoded.sub, {
      include: [{ model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] }],
    });
    if (user && user.active) {
      req.user = user;
      req.tokenScopes = (decoded.scope || "").split(" ");
    }
  } catch {
    // Silently ignore invalid tokens
  }
  next();
}

module.exports = { authenticate, requireRole, requirePermission, optionalAuth };
