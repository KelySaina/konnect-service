const nodemailer = require('nodemailer');

// Lazy transporter initialization
let transporter = null;

const getTransporter = () => {
  if (!transporter && process.env.SMTP_HOST) {
    transporter = nodemailer.createTransport({
      host: process.env.SMTP_HOST,
      port: process.env.SMTP_PORT,
      secure: false,
      auth: {
        user: process.env.SMTP_USER,
        pass: process.env.SMTP_PASSWORD
      }
    });
  }
  return transporter;
};

const sendPasswordResetEmail = async (email, token) => {
  const transport = getTransporter();

  if (!transport) {
    console.warn('Email not configured. Password reset email not sent.');
    return;
  }

  // Use APP_URL or fallback to localhost:3000
  const baseUrl = process.env.APP_URL || 'http://localhost:3000';
  const resetUrl = `${baseUrl}/reset-password?token=${token}`;

  const mailOptions = {
    from: process.env.EMAIL_FROM,
    to: email,
    subject: 'Password Reset Request - Konnect Service',
    html: `
      <h2>Password Reset Request</h2>
      <p>You requested to reset your password. Click the link below to reset it:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p>This link will expire in 1 hour.</p>
      <p>If you didn't request this, please ignore this email.</p>
      <br>
      <p>Best regards,<br>Konnect Service Team</p>
    `
  };

  try {
    await transport.sendMail(mailOptions);
    console.log('Password reset email sent to:', email);
  } catch (error) {
    console.error('Failed to send email:', error);
    // Don't throw error to prevent email enumeration
  }
};

module.exports = {
  sendPasswordResetEmail
};
