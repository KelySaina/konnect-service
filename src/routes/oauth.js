const express = require('express');
const router = express.Router();
const oauthController = require('../controllers/oauthController');

// OAuth 2.0 / OpenID Connect endpoints
router.get('/authorize', oauthController.authorize);
router.post('/authorize', oauthController.authorizePost);
router.post('/token', oauthController.token);
router.get('/userinfo', oauthController.userinfo);
router.post('/revoke', oauthController.revoke);

module.exports = router;
