const { v4: uuidv4 } = require('uuid');
const bcrypt = require('bcryptjs');
const pool = require('../config/database');
const { generateAccessToken, generateRefreshToken, verifyRefreshToken } = require('../utils/jwt');
const { sendPasswordResetEmail } = require('../utils/email');
const speakeasy = require('speakeasy');
const QRCode = require('qrcode');

// Register new user
const register = async (req, res) => {
  try {
    const { email, password, first_name, last_name } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Check if user already exists
    const [existingUsers] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);
    if (existingUsers.length > 0) {
      return res.status(409).json({ error: 'User already exists' });
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, parseInt(process.env.BCRYPT_ROUNDS) || 10);

    // Create user
    const userId = uuidv4();
    await pool.query(
      'INSERT INTO users (id, email, password, first_name, last_name) VALUES (?, ?, ?, ?, ?)',
      [userId, email, hashedPassword, first_name || null, last_name || null]
    );

    res.status(201).json({
      message: 'User registered successfully',
      user: {
        id: userId,
        email,
        first_name,
        last_name
      }
    });
  } catch (error) {
    console.error('Register error:', error);
    res.status(500).json({ error: 'Registration failed' });
  }
};

// Login user
const login = async (req, res) => {
  try {
    const { email, password, mfa_code } = req.body;

    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Get user
    const [users] = await pool.query(
      'SELECT * FROM users WHERE email = ? AND is_active = true',
      [email]
    );

    if (users.length === 0) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    const user = users[0];

    // Verify password
    const validPassword = await bcrypt.compare(password, user.password);
    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid credentials' });
    }

    // Check MFA
    if (user.mfa_enabled) {
      if (!mfa_code) {
        return res.status(200).json({ mfa_required: true });
      }

      // Verify MFA code
      const [mfaSecrets] = await pool.query(
        'SELECT secret FROM mfa_secrets WHERE user_id = ?',
        [user.id]
      );

      if (mfaSecrets.length === 0) {
        return res.status(500).json({ error: 'MFA configuration error' });
      }

      const verified = speakeasy.totp.verify({
        secret: mfaSecrets[0].secret,
        encoding: 'base32',
        token: mfa_code,
        window: 2
      });

      if (!verified) {
        return res.status(401).json({ error: 'Invalid MFA code' });
      }
    }

    // Generate tokens
    const accessToken = generateAccessToken({
      userId: user.id,
      email: user.email
    });

    const refreshToken = generateRefreshToken({
      userId: user.id,
      email: user.email
    });

    res.json({
      access_token: accessToken,
      refresh_token: refreshToken,
      token_type: 'Bearer',
      expires_in: 900, // 15 minutes
      user: {
        id: user.id,
        email: user.email,
        first_name: user.first_name,
        last_name: user.last_name,
        mfa_enabled: user.mfa_enabled
      }
    });
  } catch (error) {
    console.error('Login error:', error);
    res.status(500).json({ error: 'Login failed' });
  }
};

// Refresh token
const refresh = async (req, res) => {
  try {
    const { refresh_token } = req.body;

    if (!refresh_token) {
      return res.status(400).json({ error: 'Refresh token required' });
    }

    // Verify refresh token
    const decoded = verifyRefreshToken(refresh_token);

    // Generate new access token
    const accessToken = generateAccessToken({
      userId: decoded.userId,
      email: decoded.email
    });

    res.json({
      access_token: accessToken,
      token_type: 'Bearer',
      expires_in: 900
    });
  } catch (error) {
    console.error('Refresh error:', error);
    res.status(403).json({ error: 'Invalid or expired refresh token' });
  }
};

// Get current user
const getMe = async (req, res) => {
  try {
    const [users] = await pool.query(
      'SELECT id, email, first_name, last_name, is_verified, mfa_enabled, created_at FROM users WHERE id = ?',
      [req.user.userId]
    );

    if (users.length === 0) {
      return res.status(404).json({ error: 'User not found' });
    }

    res.json(users[0]);
  } catch (error) {
    console.error('Get me error:', error);
    res.status(500).json({ error: 'Failed to fetch user' });
  }
};

// Logout (optional - mainly for token revocation if implemented)
const logout = async (req, res) => {
  // In a stateless JWT system, logout is typically handled client-side
  // by removing the tokens. However, you could implement token blacklisting here.
  res.json({ message: 'Logged out successfully' });
};

// Forgot password
const forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res.status(400).json({ error: 'Email is required' });
    }

    // Check if user exists
    const [users] = await pool.query('SELECT id FROM users WHERE email = ?', [email]);

    // Always return success to prevent email enumeration
    if (users.length === 0) {
      return res.json({ message: 'If the email exists, a reset link has been sent' });
    }

    const user = users[0];

    // Generate reset token
    const resetToken = uuidv4();
    const expiresAt = new Date(Date.now() + 3600000); // 1 hour

    await pool.query(
      'INSERT INTO password_reset_tokens (id, user_id, token, expires_at) VALUES (?, ?, ?, ?)',
      [uuidv4(), user.id, resetToken, expiresAt]
    );

    // Send email (implement this in email utility)
    await sendPasswordResetEmail(email, resetToken);

    res.json({ message: 'If the email exists, a reset link has been sent' });
  } catch (error) {
    console.error('Forgot password error:', error);
    res.status(500).json({ error: 'Failed to process request' });
  }
};

// Reset password
const resetPassword = async (req, res) => {
  try {
    const { token, new_password } = req.body;

    if (!token || !new_password) {
      return res.status(400).json({ error: 'Token and new password are required' });
    }

    // Verify token
    const [tokens] = await pool.query(
      'SELECT * FROM password_reset_tokens WHERE token = ? AND expires_at > NOW() AND used = false',
      [token]
    );

    if (tokens.length === 0) {
      return res.status(400).json({ error: 'Invalid or expired token' });
    }

    const resetToken = tokens[0];

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, parseInt(process.env.BCRYPT_ROUNDS) || 10);

    // Update password
    await pool.query('UPDATE users SET password = ? WHERE id = ?', [hashedPassword, resetToken.user_id]);

    // Mark token as used
    await pool.query('UPDATE password_reset_tokens SET used = true WHERE id = ?', [resetToken.id]);

    res.json({ message: 'Password reset successfully' });
  } catch (error) {
    console.error('Reset password error:', error);
    res.status(500).json({ error: 'Failed to reset password' });
  }
};

// Enable MFA
const enableMFA = async (req, res) => {
  try {
    const userId = req.user.userId;

    // Check if MFA already enabled
    const [users] = await pool.query('SELECT mfa_enabled FROM users WHERE id = ?', [userId]);
    if (users[0].mfa_enabled) {
      return res.status(400).json({ error: 'MFA already enabled' });
    }

    // Generate secret
    const secret = speakeasy.generateSecret({
      name: `Konnect Service (${req.user.email})`
    });

    // Save secret (not activated yet)
    const [existing] = await pool.query('SELECT id FROM mfa_secrets WHERE user_id = ?', [userId]);

    if (existing.length > 0) {
      await pool.query('UPDATE mfa_secrets SET secret = ? WHERE user_id = ?', [secret.base32, userId]);
    } else {
      await pool.query(
        'INSERT INTO mfa_secrets (id, user_id, secret) VALUES (?, ?, ?)',
        [uuidv4(), userId, secret.base32]
      );
    }

    // Generate QR code
    const qrCode = await QRCode.toDataURL(secret.otpauth_url);

    res.json({
      secret: secret.base32,
      qr_code: qrCode,
      message: 'Scan the QR code with your authenticator app and verify'
    });
  } catch (error) {
    console.error('Enable MFA error:', error);
    res.status(500).json({ error: 'Failed to enable MFA' });
  }
};

// Verify and activate MFA
const verifyMFA = async (req, res) => {
  try {
    const { code } = req.body;
    const userId = req.user.userId;

    if (!code) {
      return res.status(400).json({ error: 'Verification code required' });
    }

    // Get secret
    const [secrets] = await pool.query('SELECT secret FROM mfa_secrets WHERE user_id = ?', [userId]);

    if (secrets.length === 0) {
      return res.status(400).json({ error: 'MFA not initialized' });
    }

    // Verify code
    const verified = speakeasy.totp.verify({
      secret: secrets[0].secret,
      encoding: 'base32',
      token: code,
      window: 2
    });

    if (!verified) {
      return res.status(401).json({ error: 'Invalid verification code' });
    }

    // Activate MFA
    await pool.query('UPDATE users SET mfa_enabled = true WHERE id = ?', [userId]);

    res.json({ message: 'MFA enabled successfully' });
  } catch (error) {
    console.error('Verify MFA error:', error);
    res.status(500).json({ error: 'Failed to verify MFA' });
  }
};

// Disable MFA
const disableMFA = async (req, res) => {
  try {
    const { password } = req.body;
    const userId = req.user.userId;

    if (!password) {
      return res.status(400).json({ error: 'Password required' });
    }

    // Verify password
    const [users] = await pool.query('SELECT password FROM users WHERE id = ?', [userId]);
    const validPassword = await bcrypt.compare(password, users[0].password);

    if (!validPassword) {
      return res.status(401).json({ error: 'Invalid password' });
    }

    // Disable MFA
    await pool.query('UPDATE users SET mfa_enabled = false WHERE id = ?', [userId]);
    await pool.query('DELETE FROM mfa_secrets WHERE user_id = ?', [userId]);

    res.json({ message: 'MFA disabled successfully' });
  } catch (error) {
    console.error('Disable MFA error:', error);
    res.status(500).json({ error: 'Failed to disable MFA' });
  }
};

module.exports = {
  register,
  login,
  refresh,
  logout,
  getMe,
  forgotPassword,
  resetPassword,
  enableMFA,
  verifyMFA,
  disableMFA
};
