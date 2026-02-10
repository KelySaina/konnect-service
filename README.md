# Konnect Service (KS)

A comprehensive Identity Provider (IDP) and Single Sign-On (SSO) service with OAuth 2.0, OpenID Connect, and Multi-Factor Authentication support.

## Features

- ✅ User Registration & Login
- ✅ OAuth 2.0 & OpenID Connect Support
- ✅ Password Reset via Email
- ✅ Multi-Factor Authentication (TOTP)
- ✅ Admin Dashboard
- ✅ Rate Limiting & Security Headers
- ✅ JWT Token Management
- ✅ Client Application Management

## Quick Start

### 1. Install Dependencies

```bash
npm install
```

### 2. Configure Environment

Copy `.env.example` to `.env` and update the values:

```bash
cp .env.example .env
```

### 3. Setup Database

Create a MySQL database and run migrations:

```bash
npm run migrate
```

Optional: Seed with sample data:

```bash
npm run seed
```

### 4. Start the Server

Development mode:
```bash
npm run dev
```

Production mode:
```bash
npm start
```

The service will be available at `http://localhost:3000`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - Login user
- `POST /api/auth/logout` - Logout user
- `POST /api/auth/refresh` - Refresh access token
- `POST /api/auth/forgot-password` - Request password reset
- `POST /api/auth/reset-password` - Reset password with token

### MFA
- `POST /api/auth/mfa/enable` - Enable MFA
- `POST /api/auth/mfa/verify` - Verify MFA code
- `POST /api/auth/mfa/disable` - Disable MFA

### OAuth 2.0 / OpenID Connect
- `GET /oauth/authorize` - Authorization endpoint
- `POST /oauth/token` - Token endpoint
- `GET /oauth/userinfo` - User info endpoint
- `POST /oauth/revoke` - Token revocation

### Admin Dashboard
- `GET /admin` - Admin dashboard UI
- `GET /api/admin/users` - List all users
- `GET /api/admin/clients` - List OAuth clients
- `POST /api/admin/clients` - Create OAuth client
- `DELETE /api/admin/clients/:id` - Delete OAuth client

## Integration with Your Apps

### 1. Register Your Application

Create an OAuth client in the admin dashboard or via API:

```bash
POST /api/admin/clients
{
  "name": "My App",
  "redirect_uris": ["http://localhost:4000/callback"],
  "grant_types": ["authorization_code", "refresh_token"]
}
```

You'll receive a `client_id` and `client_secret`.

### 2. Implement OAuth Flow in Your App

Redirect users to:
```
http://localhost:3000/oauth/authorize?response_type=code&client_id=YOUR_CLIENT_ID&redirect_uri=YOUR_REDIRECT_URI&scope=openid profile email
```

Exchange code for tokens:
```bash
POST /oauth/token
{
  "grant_type": "authorization_code",
  "code": "authorization_code",
  "client_id": "YOUR_CLIENT_ID",
  "client_secret": "YOUR_CLIENT_SECRET",
  "redirect_uri": "YOUR_REDIRECT_URI"
}
```

### 3. Get User Info

```bash
GET /oauth/userinfo
Authorization: Bearer ACCESS_TOKEN
```

## Database Schema

The service uses the following tables:
- `users` - User accounts
- `oauth_clients` - Registered OAuth clients
- `oauth_authorization_codes` - Authorization codes
- `oauth_access_tokens` - Access tokens
- `oauth_refresh_tokens` - Refresh tokens
- `password_reset_tokens` - Password reset tokens
- `mfa_secrets` - MFA secrets

## Security Features

- Password hashing with bcrypt
- JWT tokens with expiration
- Rate limiting on authentication endpoints
- CORS protection
- Helmet security headers
- SQL injection prevention
- TOTP-based MFA

## License

MIT
