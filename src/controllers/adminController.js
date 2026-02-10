const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const pool = require('../config/database');

// Get all users
const getUsers = async (req, res) => {
  try {
    const { page = 1, limit = 20 } = req.query;
    const offset = (page - 1) * limit;

    const [users] = await pool.query(
      `SELECT id, email, first_name, last_name, is_active, is_verified, mfa_enabled, created_at
       FROM users
       ORDER BY created_at DESC
       LIMIT ? OFFSET ?`,
      [parseInt(limit), parseInt(offset)]
    );

    const [countResult] = await pool.query('SELECT COUNT(*) as total FROM users');
    const total = countResult[0].total;

    res.json({
      users,
      pagination: {
        page: parseInt(page),
        limit: parseInt(limit),
        total,
        pages: Math.ceil(total / limit)
      }
    });
  } catch (error) {
    console.error('Get users error:', error);
    res.status(500).json({ error: 'Failed to fetch users' });
  }
};

// Get user by ID
const getUserById = async (req, res) => {
  try {
    const { id } = req.params;

    const [users] = await pool.query(
      'SELECT id, email, first_name, last_name, is_active, is_verified, mfa_enabled, created_at FROM users WHERE id = ?',
      [id]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(users[0]);
  } catch (error) {
    console.error('Get user error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
};

// Update user
const updateUser = async (req, res) => {
  try {
    const { id } = req.params;
    const { first_name, last_name, is_active, is_verified } = req.body;

    await pool.query(
      'UPDATE users SET first_name = ?, last_name = ?, is_active = ?, is_verified = ? WHERE id = ?',
      [first_name, last_name, is_active, is_verified, id]
    );

    res.json({ message: 'User updated successfully' });
  } catch (error) {
    console.error('Update user error:', error);
    res.status(500).json({ error: 'Failed to update user' });
  }
};

// Delete user
const deleteUser = async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM users WHERE id = ?', [id]);

    res.json({ message: 'User deleted successfully' });
  } catch (error) {
    console.error('Delete user error:', error);
    res.status(500).json({ error: 'Failed to delete user' });
  }
};

// Get all OAuth clients
const getClients = async (req, res) => {
  try {
    const [clients] = await pool.query(
      `SELECT id, client_id, name, redirect_uris, grant_types, scope, is_active, created_at
       FROM oauth_clients
       ORDER BY created_at DESC`
    );

    // Parse JSON fields
    const formattedClients = clients.map(client => ({
      ...client,
      redirect_uris: JSON.parse(client.redirect_uris)
    }));

    res.json(formattedClients);
  } catch (error) {
    console.error('Get clients error:', error);
    res.status(500).json({ error: 'Failed to fetch clients' });
  }
};

// Create OAuth client
const createClient = async (req, res) => {
  try {
    const { name, redirect_uris, grant_types = 'authorization_code,refresh_token', scope = 'openid profile email' } = req.body;

    if (!name || !redirect_uris || redirect_uris.length === 0) {
      return res.status(400).json({ error: 'Name and redirect URIs are required' });
    }

    const clientId = `client_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const clientSecret = `secret_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    const hashedSecret = await bcrypt.hash(clientSecret, parseInt(process.env.BCRYPT_ROUNDS) || 10);

    const id = uuidv4();

    await pool.query(
      'INSERT INTO oauth_clients (id, client_id, client_secret, name, redirect_uris, grant_types, scope) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [id, clientId, hashedSecret, name, JSON.stringify(redirect_uris), grant_types, scope]
    );

    res.status(201).json({
      id,
      client_id: clientId,
      client_secret: clientSecret, // Return plain secret only once
      name,
      redirect_uris,
      grant_types,
      scope,
      message: 'Client created successfully. Save the client_secret securely - it will not be shown again.'
    });
  } catch (error) {
    console.error('Create client error:', error);
    res.status(500).json({ error: 'Failed to create client' });
  }
};

// Update OAuth client
const updateClient = async (req, res) => {
  try {
    const { id } = req.params;
    const { name, redirect_uris, grant_types, scope, is_active } = req.body;

    await pool.query(
      'UPDATE oauth_clients SET name = ?, redirect_uris = ?, grant_types = ?, scope = ?, is_active = ? WHERE id = ?',
      [name, JSON.stringify(redirect_uris), grant_types, scope, is_active, id]
    );

    res.json({ message: 'Client updated successfully' });
  } catch (error) {
    console.error('Update client error:', error);
    res.status(500).json({ error: 'Failed to update client' });
  }
};

// Delete OAuth client
const deleteClient = async (req, res) => {
  try {
    const { id } = req.params;

    await pool.query('DELETE FROM oauth_clients WHERE id = ?', [id]);

    res.json({ message: 'Client deleted successfully' });
  } catch (error) {
    console.error('Delete client error:', error);
    res.status(500).json({ error: 'Failed to delete client' });
  }
};

// Get dashboard statistics
const getStats = async (req, res) => {
  try {
    const [userCount] = await pool.query('SELECT COUNT(*) as count FROM users');
    const [activeUsers] = await pool.query('SELECT COUNT(*) as count FROM users WHERE is_active = true');
    const [clientCount] = await pool.query('SELECT COUNT(*) as count FROM oauth_clients');
    const [tokenCount] = await pool.query('SELECT COUNT(*) as count FROM oauth_access_tokens');

    res.json({
      total_users: userCount[0].count,
      active_users: activeUsers[0].count,
      total_clients: clientCount[0].count,
      active_tokens: tokenCount[0].count
    });
  } catch (error) {
    console.error('Get stats error:', error);
    res.status(500).json({ error: 'Failed to fetch statistics' });
  }
};

module.exports = {
  getUsers,
  getUserById,
  updateUser,
  deleteUser,
  getClients,
  createClient,
  updateClient,
  deleteClient,
  getStats
};
