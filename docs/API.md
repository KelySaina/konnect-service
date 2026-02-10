# API Documentation

Complete API reference for Konnect Service.

## Base URL

```
http://localhost:3000
```

---

## Authentication Endpoints

### Register User

Create a new user account.

**Endpoint:** `POST /api/auth/register`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "securePassword123",
  "first_name": "John",
  "last_name": "Doe"
}
```

**Response:** `201 Created`
```json
{
  "message": "User registered successfully",
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe"
  }
}
```

**Errors:**
- `400` - Missing required fields
- `409` - User already exists

---

### Login

Authenticate user and receive tokens.

**Endpoint:** `POST /api/auth/login`

**Request Body:**
```json
{
  "email": "user@example.com",
  "password": "password123",
  "mfa_code": "123456"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "d2e4f6g8h0j2k4m6n8p0...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "uuid",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "mfa_enabled": false
  }
}
```

**MFA Required Response:** `200 OK`
```json
{
  "mfa_required": true
}
```

**Errors:**
- `400` - Missing credentials
- `401` - Invalid credentials or MFA code

---

### Refresh Token

Get a new access token using refresh token.

**Endpoint:** `POST /api/auth/refresh`

**Request Body:**
```json
{
  "refresh_token": "your_refresh_token"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 900
}
```

**Errors:**
- `400` - Missing refresh token
- `403` - Invalid or expired refresh token

---

### Get Current User

Get information about the authenticated user.

**Endpoint:** `GET /api/auth/me`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_verified": true,
  "mfa_enabled": false,
  "created_at": "2026-01-01T00:00:00.000Z"
}
```

**Errors:**
- `401` - Missing or invalid token
- `404` - User not found

---

### Logout

Logout the user (client-side token removal).

**Endpoint:** `POST /api/auth/logout`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:** `200 OK`
```json
{
  "message": "Logged out successfully"
}
```

---

### Forgot Password

Request a password reset link.

**Endpoint:** `POST /api/auth/forgot-password`

**Request Body:**
```json
{
  "email": "user@example.com"
}
```

**Response:** `200 OK`
```json
{
  "message": "If the email exists, a reset link has been sent"
}
```

---

### Reset Password

Reset password using token from email.

**Endpoint:** `POST /api/auth/reset-password`

**Request Body:**
```json
{
  "token": "reset_token_from_email",
  "new_password": "newSecurePassword123"
}
```

**Response:** `200 OK`
```json
{
  "message": "Password reset successfully"
}
```

**Errors:**
- `400` - Missing fields or invalid/expired token

---

## MFA Endpoints

### Enable MFA

Initialize MFA for the user and get QR code.

**Endpoint:** `POST /api/auth/mfa/enable`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:** `200 OK`
```json
{
  "secret": "JBSWY3DPEHPK3PXP",
  "qr_code": "data:image/png;base64,iVBORw0KG...",
  "message": "Scan the QR code with your authenticator app and verify"
}
```

**Errors:**
- `400` - MFA already enabled
- `401` - Invalid token

---

### Verify MFA

Verify MFA code and activate MFA.

**Endpoint:** `POST /api/auth/mfa/verify`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "code": "123456"
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA enabled successfully"
}
```

**Errors:**
- `400` - Missing code or MFA not initialized
- `401` - Invalid verification code

---

### Disable MFA

Disable MFA for the user.

**Endpoint:** `POST /api/auth/mfa/disable`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Request Body:**
```json
{
  "password": "current_password"
}
```

**Response:** `200 OK`
```json
{
  "message": "MFA disabled successfully"
}
```

**Errors:**
- `400` - Missing password
- `401` - Invalid password

---

## OAuth 2.0 / OpenID Connect Endpoints

### Authorization Endpoint

Start OAuth 2.0 authorization flow.

**Endpoint:** `GET /oauth/authorize`

**Query Parameters:**
- `response_type` (required): `code`
- `client_id` (required): Your client ID
- `redirect_uri` (required): Your registered redirect URI
- `scope` (optional): Space-separated scopes (default: `openid profile email`)
- `state` (recommended): Random string for CSRF protection

**Example:**
```
GET /oauth/authorize?response_type=code&client_id=your_client_id&redirect_uri=http://localhost:4000/callback&scope=openid%20profile%20email&state=xyz123
```

**Response:**
Returns HTML login page where user can authorize.

After authorization, redirects to:
```
{redirect_uri}?code=authorization_code&state=xyz123
```

**Errors:**
- `400` - Invalid request parameters
- `401` - Invalid client

---

### Token Endpoint

Exchange authorization code for tokens or refresh access token.

**Endpoint:** `POST /oauth/token`

#### Authorization Code Grant

**Request Body:**
```json
{
  "grant_type": "authorization_code",
  "code": "authorization_code",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret",
  "redirect_uri": "http://localhost:4000/callback"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "d2e4f6g8h0j2k4m6n8p0...",
  "id_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "scope": "openid profile email"
}
```

#### Refresh Token Grant

**Request Body:**
```json
{
  "grant_type": "refresh_token",
  "refresh_token": "your_refresh_token",
  "client_id": "your_client_id",
  "client_secret": "your_client_secret"
}
```

**Response:** `200 OK`
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 3600
}
```

**Errors:**
- `400` - Invalid request or grant
- `401` - Invalid client credentials

---

### UserInfo Endpoint

Get user information (OpenID Connect).

**Endpoint:** `GET /oauth/userinfo`

**Headers:**
```
Authorization: Bearer {access_token}
```

**Response:** `200 OK`
```json
{
  "sub": "user_id",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "updated_at": 1640995200
}
```

**Errors:**
- `401` - Invalid or missing token

---

### Revoke Token

Revoke a refresh token.

**Endpoint:** `POST /oauth/revoke`

**Request Body:**
```json
{
  "token": "refresh_token_to_revoke",
  "token_type_hint": "refresh_token"
}
```

**Response:** `200 OK`
```json
{
  "message": "Token revoked successfully"
}
```

---

## Admin Endpoints

All admin endpoints require authentication via `Authorization: Bearer {access_token}` header.

### Get Dashboard Statistics

**Endpoint:** `GET /api/admin/stats`

**Response:** `200 OK`
```json
{
  "total_users": 42,
  "active_users": 38,
  "total_clients": 5,
  "active_tokens": 120
}
```

---

### List Users

**Endpoint:** `GET /api/admin/users`

**Query Parameters:**
- `page` (optional): Page number (default: 1)
- `limit` (optional): Items per page (default: 20)

**Response:** `200 OK`
```json
{
  "users": [
    {
      "id": "uuid",
      "email": "user@example.com",
      "first_name": "John",
      "last_name": "Doe",
      "is_active": true,
      "is_verified": true,
      "mfa_enabled": false,
      "created_at": "2026-01-01T00:00:00.000Z"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 20,
    "total": 42,
    "pages": 3
  }
}
```

---

### Get User by ID

**Endpoint:** `GET /api/admin/users/:id`

**Response:** `200 OK`
```json
{
  "id": "uuid",
  "email": "user@example.com",
  "first_name": "John",
  "last_name": "Doe",
  "is_active": true,
  "is_verified": true,
  "mfa_enabled": false,
  "created_at": "2026-01-01T00:00:00.000Z"
}
```

**Errors:**
- `404` - User not found

---

### Update User

**Endpoint:** `PUT /api/admin/users/:id`

**Request Body:**
```json
{
  "first_name": "Jane",
  "last_name": "Smith",
  "is_active": true,
  "is_verified": true
}
```

**Response:** `200 OK`
```json
{
  "message": "User updated successfully"
}
```

---

### Delete User

**Endpoint:** `DELETE /api/admin/users/:id`

**Response:** `200 OK`
```json
{
  "message": "User deleted successfully"
}
```

---

### List OAuth Clients

**Endpoint:** `GET /api/admin/clients`

**Response:** `200 OK`
```json
[
  {
    "id": "uuid",
    "client_id": "client_123",
    "name": "My App",
    "redirect_uris": ["http://localhost:4000/callback"],
    "grant_types": "authorization_code,refresh_token",
    "scope": "openid profile email",
    "is_active": true,
    "created_at": "2026-01-01T00:00:00.000Z"
  }
]
```

---

### Create OAuth Client

**Endpoint:** `POST /api/admin/clients`

**Request Body:**
```json
{
  "name": "My Application",
  "redirect_uris": ["http://localhost:4000/callback"],
  "grant_types": "authorization_code,refresh_token",
  "scope": "openid profile email"
}
```

**Response:** `201 Created`
```json
{
  "id": "uuid",
  "client_id": "client_123",
  "client_secret": "secret_456",
  "name": "My Application",
  "redirect_uris": ["http://localhost:4000/callback"],
  "grant_types": "authorization_code,refresh_token",
  "scope": "openid profile email",
  "message": "Client created successfully. Save the client_secret securely - it will not be shown again."
}
```

⚠️ **The `client_secret` is only returned once!**

---

### Update OAuth Client

**Endpoint:** `PUT /api/admin/clients/:id`

**Request Body:**
```json
{
  "name": "Updated App Name",
  "redirect_uris": ["http://localhost:4000/callback"],
  "grant_types": "authorization_code,refresh_token",
  "scope": "openid profile email",
  "is_active": true
}
```

**Response:** `200 OK`
```json
{
  "message": "Client updated successfully"
}
```

---

### Delete OAuth Client

**Endpoint:** `DELETE /api/admin/clients/:id`

**Response:** `200 OK`
```json
{
  "message": "Client deleted successfully"
}
```

---

## Error Responses

All endpoints may return error responses in this format:

```json
{
  "error": "error_code",
  "error_description": "Human-readable error description"
}
```

### Common HTTP Status Codes

- `200` - Success
- `201` - Created
- `400` - Bad Request (invalid parameters)
- `401` - Unauthorized (invalid credentials or token)
- `403` - Forbidden (valid token but insufficient permissions)
- `404` - Not Found
- `409` - Conflict (e.g., user already exists)
- `500` - Internal Server Error

---

## Rate Limiting

Authentication endpoints are rate-limited to prevent abuse:

- **Window:** 15 minutes
- **Max Requests:** 100 per IP

When rate limit is exceeded:

**Response:** `429 Too Many Requests`
```json
{
  "error": "Too many requests from this IP, please try again later."
}
```

---

## CORS

The service supports CORS for configured frontend URLs. Set `FRONTEND_URL` in `.env` to allow requests from your frontend application.

---

## Security Headers

The service includes security headers via Helmet.js:
- X-Content-Type-Options
- X-Frame-Options
- Strict-Transport-Security
- X-XSS-Protection

---

## JWT Token Structure

### Access Token Payload

```json
{
  "userId": "uuid",
  "email": "user@example.com",
  "iat": 1640995200,
  "exp": 1640996100
}
```

### ID Token Payload (OpenID Connect)

```json
{
  "sub": "uuid",
  "email": "user@example.com",
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe",
  "email_verified": true,
  "iss": "http://localhost:3000",
  "aud": "client_id",
  "iat": 1640995200,
  "exp": 1640998800
}
```
