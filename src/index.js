const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const morgan = require("morgan");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const RedisStore = require("connect-redis").default;
const Redis = require("ioredis");
const config = require("./config");
const { sequelize } = require("./models");
const { createApolloServer } = require("./graphql");
const oauthRoutes = require("./routes/oauth");
const userRoutes = require("./routes/users");
const errorHandler = require("./middleware/errorHandler");

async function bootstrap() {
  const app = express();

  // Core middleware
  app.use(helmet({ contentSecurityPolicy: false }));
  app.use(cors({ origin: config.clientUrl, credentials: true }));
  app.use(express.json());
  app.use(cookieParser());
  app.use(morgan("short"));

  // Session (for OAuth authorize consent flow)
  // Redis is optional in dev — falls back to in-memory sessions
  let sessionStore;
  try {
    const redisClient = new Redis({
      host: config.redis.host,
      port: config.redis.port,
      maxRetriesPerRequest: 3,
      retryStrategy(times) {
        if (times > 3) return null; // stop retrying
        return Math.min(times * 200, 2000);
      },
      lazyConnect: true,
    });
    redisClient.on("error", () => {}); // suppress unhandled error events
    await redisClient.connect();
    sessionStore = new RedisStore({ client: redisClient });
    console.log("[redis] Connected");
  } catch {
    console.warn("[redis] Not available — using in-memory sessions (dev only)");
    sessionStore = undefined;
  }

  const sessionConfig = {
    secret: config.session.secret,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: config.env === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24h
    },
  };
  if (sessionStore) sessionConfig.store = sessionStore;
  app.use(session(sessionConfig));

  // Health check
  app.get("/health", (_req, res) => res.json({ status: "ok" }));

  // ---------- REST — OAuth2/OIDC ----------
  app.use(oauthRoutes);

  // ---------- REST — User routes (avatar upload, file serving) ----------
  app.use("/api", userRoutes);

  // ---------- GraphQL ----------
  const { middleware: graphqlMiddleware } = await createApolloServer();
  app.use("/graphql", graphqlMiddleware);

  // ---------- Error handler ----------
  app.use(errorHandler);

  // ---------- Start ----------
  await sequelize.authenticate();
  console.log("[db] Connected to PostgreSQL");

  // Auto-migrate (alter mode) and seed
  await sequelize.sync({ alter: true });
  console.log("[db] Schema synced");

  try {
    const { seed } = require("./database/seed");
    await seed();
    console.log("[db] Seed complete");
  } catch (err) {
    console.warn("[db] Seed skipped or failed:", err.message);
  }

  app.listen(config.port, () => {
    console.log(`[konnect] API running on http://localhost:${config.port}`);
    console.log(`[konnect] GraphQL playground at http://localhost:${config.port}/graphql`);
    console.log(`[konnect] OIDC discovery at http://localhost:${config.port}/.well-known/openid-configuration`);
  });
}

bootstrap().catch((err) => {
  console.error("[konnect] Fatal error:", err);
  process.exit(1);
});
