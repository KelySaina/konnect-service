const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const pool = require('../config/database');

const seedDatabase = async () => {
  const connection = await pool.getConnection();

  try {
    console.log('Seeding database...');

    // Create admin user
    const adminId = uuidv4();
    const adminPassword = await bcrypt.hash('admin123', 10);

    await connection.query(
      `INSERT INTO users (id, email, password, first_name, last_name, is_active, is_verified)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE email=email`,
      [adminId, 'admin@konnect-service.com', adminPassword, 'Admin', 'User', true, true]
    );
    console.log('✅ Admin user created (email: admin@konnect-service.com, password: admin123)');

    // Create test user
    const testUserId = uuidv4();
    const testPassword = await bcrypt.hash('test123', 10);

    await connection.query(
      `INSERT INTO users (id, email, password, first_name, last_name, is_active, is_verified)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE email=email`,
      [testUserId, 'test@example.com', testPassword, 'Test', 'User', true, true]
    );
    console.log('✅ Test user created (email: test@example.com, password: test123)');

    // Create sample OAuth client
    const clientId = uuidv4();
    const clientSecret = await bcrypt.hash('sample_secret_' + Date.now(), 10);

    await connection.query(
      `INSERT INTO oauth_clients (id, client_id, client_secret, name, redirect_uris, grant_types, scope)
       VALUES (?, ?, ?, ?, ?, ?, ?)
       ON DUPLICATE KEY UPDATE client_id=client_id`,
      [
        clientId,
        'sample_client_' + Date.now(),
        clientSecret,
        'Sample Application',
        JSON.stringify(['http://localhost:4000/callback']),
        'authorization_code,refresh_token',
        'openid profile email'
      ]
    );
    console.log('✅ Sample OAuth client created');

    console.log('\n✅ Database seeded successfully!');
    console.log('\n📝 Note: Check the console output for credentials');
  } catch (error) {
    console.error('❌ Seeding failed:', error.message);
    throw error;
  } finally {
    connection.release();
  }
};

// Run seed if called directly
if (require.main === module) {
  seedDatabase()
    .then(() => {
      console.log('Seeding completed');
      process.exit(0);
    })
    .catch(err => {
      console.error('Seeding error:', err);
      process.exit(1);
    });
}

module.exports = seedDatabase;
