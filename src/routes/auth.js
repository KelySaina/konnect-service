const express = require('express');
const router = express.Router();
const authController = require('../controllers/authController');
const { authenticateToken } = require('../middleware/auth');

// Public routes
router.post('/register', authController.register);
router.post('/login', authController.login);
router.post('/refresh', authController.refresh);
router.post('/forgot-password', authController.forgotPassword);
router.post('/reset-password', authController.resetPassword);

// Protected routes
router.post('/logout', authenticateToken, authController.logout);
router.get('/me', authenticateToken, authController.getMe);

// MFA routes (protected)
router.post('/mfa/enable', authenticateToken, authController.enableMFA);
router.post('/mfa/verify', authenticateToken, authController.verifyMFA);
router.post('/mfa/disable', authenticateToken, authController.disableMFA);

module.exports = router;
