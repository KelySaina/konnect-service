require("dotenv").config();

module.exports = {
  env: process.env.NODE_ENV || "development",
  port: parseInt(process.env.PORT, 10) || parseInt(process.env.API_PORT, 10) || 7300,
  apiUrl: process.env.API_URL || "http://localhost:7300",
  clientUrl: process.env.CLIENT_URL || "http://localhost:7517",

  db: {
    host: process.env.DB_HOST || "localhost",
    port: parseInt(process.env.DB_PORT, 10) || 7543,
    name: process.env.DB_NAME || "konnect",
    user: process.env.DB_USER || "konnect",
    password: process.env.DB_PASSWORD || "konnect_secret",
  },

  redis: {
    host: process.env.REDIS_HOST || "localhost",
    port: parseInt(process.env.REDIS_PORT, 10) || 7637,
  },

  minio: {
    endPoint: process.env.MINIO_ENDPOINT || "localhost",
    port: parseInt(process.env.MINIO_PORT, 10) || 7900,
    accessKey: process.env.MINIO_ACCESS_KEY || "konnect_minio",
    secretKey: process.env.MINIO_SECRET_KEY || "konnect_minio_secret",
    bucket: process.env.MINIO_BUCKET || "konnect-files",
    useSSL: process.env.MINIO_USE_SSL === "true",
  },

  jwt: {
    accessTokenTTL: parseInt(process.env.JWT_ACCESS_TOKEN_TTL, 10) || 900,
    refreshTokenTTL: parseInt(process.env.JWT_REFRESH_TOKEN_TTL, 10) || 604800,
    issuer: process.env.JWT_ISSUER || "http://localhost:7300",
  },

  oauth: {
    authCodeTTL: parseInt(process.env.OAUTH_AUTH_CODE_TTL, 10) || 600,
  },

  session: {
    secret: process.env.SESSION_SECRET || "change-me-in-production",
  },

  admin: {
    email: process.env.ADMIN_EMAIL || "admin@konnect.local",
    password: process.env.ADMIN_PASSWORD || "Admin123!",
  },
};
