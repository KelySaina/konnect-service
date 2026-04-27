const { ApolloServer } = require("@apollo/server");
const { expressMiddleware } = require("@apollo/server/express4");
const typeDefs = require("./typeDefs");
const resolvers = require("./resolvers");
const jwt = require("jsonwebtoken");
const fs = require("fs");
const path = require("path");
const { User, Role, Permission } = require("../models");

let publicKey;
try {
  publicKey = fs.readFileSync(
    path.join(__dirname, "../../keys/public.pem"),
    "utf8"
  );
} catch {
  // Fallback to HMAC if no RSA keys generated yet
  publicKey = null;
}

/**
 * Extract user from Authorization header (Bearer token).
 * Populates ctx.user with basic info + roles for resolver auth checks.
 */
async function buildContext({ req }) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return { user: null };
  }

  const token = authHeader.slice(7);
  try {
    const config = require("../config");
    const decoded = publicKey
      ? jwt.verify(token, publicKey, { algorithms: ["RS256"], issuer: config.jwt.issuer })
      : jwt.verify(token, config.session.secret, { algorithms: ["HS256"] });

    // Load full user with roles so resolvers can check permissions
    const user = await User.findByPk(decoded.sub, {
      include: [{ model: Role, as: "roles", include: [{ model: Permission, as: "permissions" }] }],
    });

    if (!user || !user.active) return { user: null };
    return { user };
  } catch {
    return { user: null };
  }
}

async function createApolloServer() {
  const server = new ApolloServer({
    typeDefs,
    resolvers,
    introspection: true, // Allow schema introspection for 3rd-party dev tools
    formatError: (formattedError) => {
      // Strip internal details in production
      if (process.env.NODE_ENV === "production") {
        delete formattedError.extensions?.stacktrace;
      }
      return formattedError;
    },
  });

  await server.start();
  return { server, middleware: expressMiddleware(server, { context: buildContext }) };
}

module.exports = { createApolloServer };
