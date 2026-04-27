const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const AuthorizationCode = sequelize.define("AuthorizationCode", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  code: {
    type: DataTypes.STRING(128),
    allowNull: false,
    unique: true,
  },
  client_id: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  redirect_uri: {
    type: DataTypes.STRING(500),
    allowNull: false,
  },
  scopes: {
    type: DataTypes.STRING(500),
    allowNull: false,
  },
  code_challenge: {
    type: DataTypes.STRING(128),
    allowNull: true,
  },
  code_challenge_method: {
    type: DataTypes.STRING(10),
    allowNull: true,
    comment: "S256 or plain",
  },
  nonce: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  expires_at: {
    type: DataTypes.DATE,
    allowNull: false,
  },
  used: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
});

module.exports = AuthorizationCode;
