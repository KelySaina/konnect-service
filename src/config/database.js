const { Sequelize } = require("sequelize");
const config = require("./index");

const sequelize = new Sequelize(config.db.name, config.db.user, config.db.password, {
  host: config.db.host,
  port: config.db.port,
  dialect: "postgres",
  logging: config.env === "development" ? console.log : false,
  define: {
    underscored: true,
    timestamps: true,
  },
  pool: {
    max: 10,
    min: 2,
    acquire: 30000,
    idle: 10000,
  },
});

module.exports = sequelize;
