const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const User = sequelize.define("User", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  email: {
    type: DataTypes.STRING(255),
    allowNull: false,
    unique: true,
    validate: { isEmail: true },
  },
  username: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
  },
  password_hash: {
    type: DataTypes.STRING(255),
    allowNull: false,
  },
  first_name: {
    type: DataTypes.STRING(100),
    allowNull: true,
  },
  last_name: {
    type: DataTypes.STRING(100),
    allowNull: true,
  },
  phone: {
    type: DataTypes.STRING(30),
    allowNull: true,
  },
  avatar_url: {
    type: DataTypes.STRING(500),
    allowNull: true,
  },
  date_of_birth: {
    type: DataTypes.DATEONLY,
    allowNull: true,
  },
  locale: {
    type: DataTypes.STRING(10),
    defaultValue: "fr",
  },
  timezone: {
    type: DataTypes.STRING(50),
    defaultValue: "Europe/Paris",
  },
  email_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  phone_verified: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
  active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {},
  },
  last_login_at: {
    type: DataTypes.DATE,
    allowNull: true,
  },
});

module.exports = User;
