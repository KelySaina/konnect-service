const { sequelize } = require("../models");

async function migrate() {
  const force = process.argv.includes("--force");
  try {
    await sequelize.authenticate();
    console.log("Database connected.");
    await sequelize.sync({ force, alter: !force });
    console.log(`Database ${force ? "reset" : "synced"} successfully.`);
  } catch (err) {
    console.error("Migration failed:", err.message);
    process.exit(1);
  } finally {
    await sequelize.close();
  }
}

migrate();
