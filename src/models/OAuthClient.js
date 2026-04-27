const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const OAuthClient = sequelize.define("OAuthClient", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  client_id: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
  },
  client_secret_hash: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: "Null for public clients (PKCE only)",
  },
  name: {
    type: DataTypes.STRING(100),
    allowNull: false,
  },
  description: {
    type: DataTypes.STRING(500),
    allowNull: true,
  },
  logo_url: {
    type: DataTypes.STRING(500),
    allowNull: true,
  },
  redirect_uris: {
    type: DataTypes.JSONB,
    defaultValue: [],
  },
  allowed_scopes: {
    type: DataTypes.JSONB,
    defaultValue: ["openid", "profile", "email"],
  },
  grant_types: {
    type: DataTypes.JSONB,
    defaultValue: ["authorization_code", "refresh_token"],
  },
  token_endpoint_auth_method: {
    type: DataTypes.STRING(50),
    defaultValue: "client_secret_basic",
    comment: "client_secret_basic, client_secret_post, none (public)",
  },
  is_confidential: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
  active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
});

module.exports = OAuthClient;
