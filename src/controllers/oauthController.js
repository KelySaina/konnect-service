const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const crypto = require('crypto');
const pool = require('../config/database');
const { generateAccessToken } = require('../utils/jwt');

// Authorization endpoint (GET)
const authorize = async (req, res) => {
  try {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope = 'openid profile email',
      state
    } = req.query;

    // Validate required parameters
    if (!response_type || !client_id || !redirect_uri) {
      // If it's a browser request (HTML), serve a user-friendly error page
      if (req.accepts('html')) {
        // Try to get the referer to send user back to their app
        const referer = req.get('referer') || req.get('referrer');
        let actionButtons = '';

        if (referer && !referer.includes(req.get('host'))) {
          // If referer exists and is from a different domain (like KaSh app)
          actionButtons = `
            <div class="actions">
              <a href="${referer}" class="btn btn-primary">← Back to App</a>
            </div>
          `;
        } else {
          // No external referer - just show a message
          actionButtons = `
            <p style="font-size: 0.9rem; color: #999; margin-top: 2rem; font-style: italic;">
              Please return to your application to log in.
            </p>
          `;
        }

        return res.status(400).send(`
          <!DOCTYPE html>
          <html lang="en">
          <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Invalid OAuth Request - Konnect</title>
            <style>
              * { margin: 0; padding: 0; box-sizing: border-box; }
              body {
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen', sans-serif;
                background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
                height: 100vh;
                display: flex;
                justify-content: center;
                align-items: center;
                padding: 1rem;
              }
              .container {
                background: white;
                padding: 3rem;
                border-radius: 16px;
                box-shadow: 0 20px 60px rgba(0, 0, 0, 0.3);
                max-width: 550px;
                width: 100%;
                text-align: center;
                animation: slideUp 0.4s ease;
              }
              @keyframes slideUp {
                from { opacity: 0; transform: translateY(20px); }
                to { opacity: 1; transform: translateY(0); }
              }
              .error-icon {
                font-size: 4rem;
                margin-bottom: 1.5rem;
                display: inline-block;
                animation: bounce 0.6s ease;
              }
              @keyframes bounce {
                0%, 100% { transform: translateY(0); }
                50% { transform: translateY(-10px); }
              }
              h1 {
                color: #333;
                font-size: 1.75rem;
                margin-bottom: 1rem;
                font-weight: 600;
              }
              .error-code {
                display: inline-block;
                background: #fee;
                color: #c33;
                padding: 0.25rem 0.75rem;
                border-radius: 6px;
                font-size: 0.85rem;
                font-weight: 600;
                margin-bottom: 1.5rem;
              }
              p {
                color: #666;
                line-height: 1.7;
                margin-bottom: 1.25rem;
                font-size: 1.05rem;
              }
              .help-text {
                background: #f8f9fa;
                padding: 1.25rem;
                border-radius: 10px;
                margin: 1.5rem 0;
                border-left: 4px solid #667eea;
              }
              .help-text strong {
                color: #333;
                display: block;
                margin-bottom: 0.5rem;
              }
              .help-text p {
                margin-bottom: 0;
                font-size: 0.95rem;
              }
              .actions {
                display: flex;
                gap: 1rem;
                margin-top: 2rem;
                flex-wrap: wrap;
                justify-content: center;
              }
              .btn {
                flex: 1;
                min-width: 140px;
                padding: 0.875rem 1.5rem;
                border-radius: 8px;
                text-decoration: none;
                font-weight: 600;
                font-size: 1rem;
                transition: all 0.2s;
                display: inline-block;
              }
              .btn-primary {
                background: #667eea;
                color: white;
              }
              .btn-primary:hover {
                background: #5568d3;
                transform: translateY(-2px);
                box-shadow: 0 4px 12px rgba(102, 126, 234, 0.4);
              }
              .btn-secondary {
                background: white;
                color: #667eea;
                border: 2px solid #667eea;
              }
              .btn-secondary:hover {
                background: #f8f9fa;
                transform: translateY(-2px);
              }
              @media (max-width: 480px) {
                .container { padding: 2rem 1.5rem; }
                h1 { font-size: 1.5rem; }
                .actions { flex-direction: column; }
                .btn { width: 100%; }
              }
            </style>
          </head>
          <body>
            <div class="container">
              <div class="error-icon">🔐</div>
              <h1>Invalid OAuth Request</h1>
              <div class="error-code">INVALID_REQUEST</div>

              <p>The OAuth authorization request is missing required parameters.</p>

              <div class="help-text">
                <strong>What does this mean?</strong>
                <p>This page requires specific OAuth parameters (client_id, redirect_uri, response_type) to authenticate you. These are typically provided automatically by your application.</p>
              </div>

              <p style="font-size: 0.95rem; margin-top: 1.5rem;">If you're trying to log in, please <strong>start from your application</strong> rather than navigating directly to this URL.</p>

              ${actionButtons}
            </div>
          </body>
          </html>
        `);
      }

      // For API requests, return JSON error
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing required parameters'
      });
    }

    // Validate response_type
    if (response_type !== 'code') {
      return res.status(400).json({
        error: 'unsupported_response_type',
        error_description: 'Only authorization_code flow is supported'
      });
    }

    // Validate client
    const [clients] = await pool.query(
      'SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = true',
      [client_id]
    );

    if (clients.length === 0) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client_id'
      });
    }

    const client = clients[0];

    // Validate redirect_uri
    const allowedUris = JSON.parse(client.redirect_uris);
    if (!allowedUris.includes(redirect_uri)) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Invalid redirect_uri'
      });
    }

    // Serve the login page
    const loginUrl = new URL('/oauth/authorize', `${req.protocol}://${req.get('host')}`);
    loginUrl.searchParams.append('client_id', client_id);
    loginUrl.searchParams.append('redirect_uri', redirect_uri);
    loginUrl.searchParams.append('scope', scope);
    if (state) loginUrl.searchParams.append('state', state);
    loginUrl.searchParams.append('client_name', client.name);

    res.sendFile('login.html', { root: './src/public' });
  } catch (error) {
    console.error('Authorize error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
};

// Register page endpoint
const showRegister = async (req, res) => {
  res.sendFile('register.html', { root: './src/public' });
};

// Authorization endpoint (POST - handle login and generate code)
const authorizePost = async (req, res) => {
  try {
    const { email, password, client_id, redirect_uri, scope, state } = req.body;

    // Authenticate user
    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ? AND is_active = true',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({
        error: 'invalid_grant',
        error_description: 'Invalid credentials'
      });
    }

    const user = users[0];
    const validPassword = await bcrypt.compare(password, user.password);

    if (!validPassword) {
      return res.status(401).json({
        error: 'invalid_grant',
        error_description: 'Invalid credentials'
      });
    }

    // Get client
    const [clients] = await pool.query(
      'SELECT id FROM oauth_clients WHERE client_id = ?',
      [client_id]
    );

    // Generate authorization code
    const code = crypto.randomBytes(32).toString('hex');
    const expiresAt = new Date(Date.now() + parseInt(process.env.OAUTH2_AUTHORIZATION_CODE_EXPIRES_IN || 600) * 1000);

    await pool.query(
      'INSERT INTO oauth_authorization_codes (id, code, client_id, user_id, redirect_uri, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?, ?)',
      [uuidv4(), code, clients[0].id, user.id, redirect_uri, scope, expiresAt]
    );

    // Build redirect URL
    const redirectUrl = new URL(redirect_uri);
    redirectUrl.searchParams.append('code', code);
    if (state) {
      redirectUrl.searchParams.append('state', state);
    }

    res.json({ redirect_uri: redirectUrl.toString() });
  } catch (error) {
    console.error('Authorize POST error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
};

// Token endpoint
const token = async (req, res) => {
  try {
    const { grant_type, code, client_id, client_secret, redirect_uri, refresh_token } = req.body;

    if (!grant_type) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing grant_type'
      });
    }

    // Validate client
    const [clients] = await pool.query(
      'SELECT * FROM oauth_clients WHERE client_id = ? AND is_active = true',
      [client_id]
    );

    if (clients.length === 0) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }

    const client = clients[0];

    // Verify client secret
    const validSecret = await bcrypt.compare(client_secret, client.client_secret);
    if (!validSecret) {
      return res.status(401).json({
        error: 'invalid_client',
        error_description: 'Invalid client credentials'
      });
    }

    if (grant_type === 'authorization_code') {
      // Exchange authorization code for tokens
      if (!code || !redirect_uri) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing required parameters'
        });
      }

      const [codes] = await pool.query(
        'SELECT * FROM oauth_authorization_codes WHERE code = ? AND client_id = ? AND redirect_uri = ? AND expires_at > NOW()',
        [code, client.id, redirect_uri]
      );

      if (codes.length === 0) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired authorization code'
        });
      }

      const authCode = codes[0];

      // Delete used authorization code
      await pool.query('DELETE FROM oauth_authorization_codes WHERE id = ?', [authCode.id]);

      // Get user info
      const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [authCode.user_id]);
      const user = users[0];

      // Generate access token
      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
        clientId: client.client_id
      });

      // Generate refresh token
      const refreshTokenValue = crypto.randomBytes(64).toString('hex');
      const refreshExpiresAt = new Date(
        Date.now() + parseInt(process.env.OAUTH2_REFRESH_TOKEN_EXPIRES_IN || 604800) * 1000
      );

      await pool.query(
        'INSERT INTO oauth_refresh_tokens (id, token, client_id, user_id, scope, expires_at) VALUES (?, ?, ?, ?, ?, ?)',
        [uuidv4(), refreshTokenValue, client.id, user.id, authCode.scope, refreshExpiresAt]
      );

      // Generate ID token (OpenID Connect)
      const idToken = generateAccessToken({
        sub: user.id,
        email: user.email,
        name: `${user.first_name || ''} ${user.last_name || ''}`.trim(),
        given_name: user.first_name,
        family_name: user.last_name,
        email_verified: user.is_verified,
        iss: process.env.APP_URL,
        aud: client.client_id
      });

      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: parseInt(process.env.OAUTH2_ACCESS_TOKEN_EXPIRES_IN || 3600),
        refresh_token: refreshTokenValue,
        id_token: idToken,
        scope: authCode.scope
      });

    } else if (grant_type === 'refresh_token') {
      // Refresh access token
      if (!refresh_token) {
        return res.status(400).json({
          error: 'invalid_request',
          error_description: 'Missing refresh_token'
        });
      }

      const [tokens] = await pool.query(
        'SELECT * FROM oauth_refresh_tokens WHERE token = ? AND client_id = ? AND expires_at > NOW()',
        [refresh_token, client.id]
      );

      if (tokens.length === 0) {
        return res.status(400).json({
          error: 'invalid_grant',
          error_description: 'Invalid or expired refresh token'
        });
      }

      const refreshTokenData = tokens[0];

      // Get user info
      const [users] = await pool.query('SELECT * FROM users WHERE id = ?', [refreshTokenData.user_id]);
      const user = users[0];

      // Generate new access token
      const accessToken = generateAccessToken({
        userId: user.id,
        email: user.email,
        clientId: client.client_id
      });

      res.json({
        access_token: accessToken,
        token_type: 'Bearer',
        expires_in: parseInt(process.env.OAUTH2_ACCESS_TOKEN_EXPIRES_IN || 3600)
      });

    } else {
      return res.status(400).json({
        error: 'unsupported_grant_type',
        error_description: 'Grant type not supported'
      });
    }
  } catch (error) {
    console.error('Token error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
};

// UserInfo endpoint (OpenID Connect)
const userinfo = async (req, res) => {
  try {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];

    if (!token) {
      return res.status(401).json({
        error: 'invalid_token',
        error_description: 'Access token required'
      });
    }

    // Verify token (using JWT utility)
    const { verifyAccessToken } = require('../utils/jwt');
    const decoded = verifyAccessToken(token);

    // Get user info
    const [users] = await pool.query(
      'SELECT id, email, first_name, last_name, is_verified, created_at FROM users WHERE id = ?',
      [decoded.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({
        error: 'invalid_token',
        error_description: 'User not found'
      });
    }

    const user = users[0];

    res.json({
      sub: user.id,
      email: user.email,
      email_verified: user.is_verified,
      name: `${user.first_name || ''} ${user.last_name || ''}`.trim(),
      given_name: user.first_name,
      family_name: user.last_name,
      updated_at: Math.floor(new Date(user.created_at).getTime() / 1000)
    });
  } catch (error) {
    console.error('UserInfo error:', error);
    res.status(401).json({
      error: 'invalid_token',
      error_description: 'Invalid or expired token'
    });
  }
};

// Token revocation endpoint
const revoke = async (req, res) => {
  try {
    const { token, token_type_hint } = req.body;

    if (!token) {
      return res.status(400).json({
        error: 'invalid_request',
        error_description: 'Missing token'
      });
    }

    // Delete refresh token
    await pool.query('DELETE FROM oauth_refresh_tokens WHERE token = ?', [token]);

    res.json({ message: 'Token revoked successfully' });
  } catch (error) {
    console.error('Revoke error:', error);
    res.status(500).json({
      error: 'server_error',
      error_description: 'Internal server error'
    });
  }
};

module.exports = {
  authorize,
  authorizePost,
  token,
  userinfo,
  revoke,
  showRegister
};
