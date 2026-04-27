const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const RefreshToken = sequelize.define("RefreshToken", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  token_hash: {
    type: DataTypes.STRING(128),
    allowNull: false,
    unique: true,
  },
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  client_id: {
    type: DataTypes.UUID,
    allowNull: true,
    comment: "Null for direct API auth (non-OAuth)",
  },
  scopes: {
    type: DataTypes.STRING(500),
    allowNull: true,
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  revoked: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  family: {
    type: DataTypes.STRING(64),
    allowNull: true,
    comment: "Token rotation family for replay detection",
  },
});

module.exports = RefreshToken;
