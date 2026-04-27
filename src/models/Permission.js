const { DataTypes } = require("sequelize");
const sequelize = require("../config/database");

const Permission = sequelize.define("Permission", {
  id: {
    type: DataTypes.UUID,
    defaultValue: DataTypes.UUIDV4,
    primaryKey: true,
  },
  name: {
    type: DataTypes.STRING(100),
    allowNull: false,
    unique: true,
  },
  description: {
    type: DataTypes.STRING(255),
    allowNull: true,
  },
  resource: {
    type: DataTypes.STRING(50),
    allowNull: false,
    comment: "e.g. users, roles, clients",
  },
  action: {
    type: DataTypes.STRING(50),
    allowNull: false,
    comment: "e.g. create, read, update, delete",
  },
});

module.exports = Permission;
