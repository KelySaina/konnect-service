const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const Organization = sequelize.define("Organization", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING(200),
    allowNull: false,
  },
  slug: {
    type: DataTypes.STRING(200),
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
  domain: {
    type: DataTypes.STRING(255),
    allowNull: true,
    comment: "Optional email domain for auto-join",
  },
  active: {
    type: DataTypes.BOOLEAN,
    defaultValue: true,
  },
  metadata: {
    type: DataTypes.JSONB,
    defaultValue: {},
  },
}, {
  indexes: [
    { unique: true, fields: ["slug"] },
    { unique: true, fields: ["domain"], where: { domain: { [require("sequelize").Op.ne]: null } } },
  ],
});

module.exports = Organization;
