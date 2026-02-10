const pool = require('../config/database');

const createTables = async () => {
  const connection = await pool.getConnection();

  try {
    console.log('Creating database schema...');

    // Users table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS users (
        id VARCHAR(36) PRIMARY KEY,
        email VARCHAR(255) UNIQUE NOT NULL,
        password VARCHAR(255) NOT NULL,
        first_name VARCHAR(100),
        last_name VARCHAR(100),
        is_active BOOLEAN DEFAULT true,
        is_verified BOOLEAN DEFAULT false,
        mfa_enabled BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_email (email)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ Users table created');

    // OAuth Clients table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS oauth_clients (
        id VARCHAR(36) PRIMARY KEY,
        client_id VARCHAR(255) UNIQUE NOT NULL,
        client_secret VARCHAR(255) NOT NULL,
        name VARCHAR(255) NOT NULL,
        redirect_uris TEXT NOT NULL,
        grant_types VARCHAR(255) NOT NULL,
        scope VARCHAR(255) DEFAULT 'openid profile email',
        is_active BOOLEAN DEFAULT true,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        INDEX idx_client_id (client_id)
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ OAuth Clients table created');

    // OAuth Authorization Codes table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS oauth_authorization_codes (
        id VARCHAR(36) PRIMARY KEY,
        code VARCHAR(255) UNIQUE NOT NULL,
        client_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        redirect_uri TEXT NOT NULL,
        scope VARCHAR(255),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_code (code),
        FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ OAuth Authorization Codes table created');

    // OAuth Access Tokens table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS oauth_access_tokens (
        id VARCHAR(36) PRIMARY KEY,
        token VARCHAR(500) UNIQUE NOT NULL,
        client_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        scope VARCHAR(255),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token),
        FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ OAuth Access Tokens table created');

    // OAuth Refresh Tokens table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS oauth_refresh_tokens (
        id VARCHAR(36) PRIMARY KEY,
        token VARCHAR(500) UNIQUE NOT NULL,
        client_id VARCHAR(36) NOT NULL,
        user_id VARCHAR(36) NOT NULL,
        scope VARCHAR(255),
        expires_at TIMESTAMP NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token),
        FOREIGN KEY (client_id) REFERENCES oauth_clients(id) ON DELETE CASCADE,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ OAuth Refresh Tokens table created');

    // Password Reset Tokens table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) NOT NULL,
        token VARCHAR(255) UNIQUE NOT NULL,
        expires_at TIMESTAMP NOT NULL,
        used BOOLEAN DEFAULT false,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        INDEX idx_token (token),
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ Password Reset Tokens table created');

    // MFA Secrets table
    await connection.query(`
      CREATE TABLE IF NOT EXISTS mfa_secrets (
        id VARCHAR(36) PRIMARY KEY,
        user_id VARCHAR(36) UNIQUE NOT NULL,
        secret VARCHAR(255) NOT NULL,
        backup_codes TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
      ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
    `);
    console.log('✅ MFA Secrets table created');

    console.log('✅ All tables created successfully!');
  } catch (error) {
    console.error('❌ Migration failed:', error.message);
    throw error;
  } finally {
    connection.release();
  }
};

// Run migration if called directly
if (require.main === module) {
  createTables()
    .then(() => {
      console.log('Migration completed');
      process.exit(0);
    })
    .catch(err => {
      console.error('Migration error:', err);
      process.exit(1);
    });
}

module.exports = createTables;
