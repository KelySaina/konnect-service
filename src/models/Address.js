const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const Address = sequelize.define("Address", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  user_id: {
    type: DataTypes.UUID,
    allowNull: false,
  },
  label: {
    type: DataTypes.STRING(50),
    defaultValue: "home",
    comment: "home, work, billing, shipping, other",
  },
  street: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  street2: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  city: {
    type: DataTypes.STRING(100),
    allowNull: true,
  },
  state: {
    type: DataTypes.STRING(100),
    allowNull: true,
  },
  postal_code: {
    type: DataTypes.STRING(20),
    allowNull: true,
  },
  country: {
    type: DataTypes.STRING(3),
    allowNull: true,
    comment: "ISO 3166-1 alpha-2/3",
  },
  is_primary: {
    type: DataTypes.BOOLEAN,
    defaultValue: false,
  },
});

module.exports = Address;
