# Client Integration Guide

This guide explains how to integrate your applications with Konnect Service.

## Table of Contents

1. [Setup](#setup)
2. [OAuth 2.0 Flow](#oauth-20-flow)
3. [Direct Authentication](#direct-authentication)
4. [Integration Examples](#integration-examples)

## Setup

### 1. Register Your Application

First, register your application as an OAuth client:

**Using Admin Dashboard:**
1. Go to `http://localhost:3000/admin`
2. Navigate to "OAuth Clients" tab
3. Click "Create Client"
4. Fill in the details:
   - Name: Your application name
   - Redirect URIs: Your callback URLs (one per line)
   - Scope: `openid profile email` (default)

**Using API:**

```bash
curl -X POST http://localhost:3000/api/admin/clients \
  -H "Authorization: Bearer {YOUR_ACCESS_TOKEN}" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "My Application",
    "redirect_uris": ["http://localhost:4000/callback"],
    "scope": "openid profile email"
  }'
```

**Response:**
```json
{
  "client_id": "client_1234567890_abc",
  "client_secret": "secret_1234567890_xyz",
  "message": "Client created successfully. Save the client_secret securely - it will not be shown again."
}
```

⚠️ **Save the `client_secret` immediately - it won't be shown again!**

---

## OAuth 2.0 Flow

The recommended approach for web applications using the Authorization Code flow with PKCE.

### Step 1: Redirect User to Authorization Endpoint

```javascript
// Generate authorization URL
const authUrl = new URL('http://localhost:3000/oauth/authorize');
authUrl.searchParams.append('response_type', 'code');
authUrl.searchParams.append('client_id', 'YOUR_CLIENT_ID');
authUrl.searchParams.append('redirect_uri', 'http://localhost:4000/callback');
authUrl.searchParams.append('scope', 'openid profile email');
authUrl.searchParams.append('state', generateRandomState()); // For CSRF protection

// Redirect user
window.location.href = authUrl.toString();
```

### Step 2: Handle Callback

After the user authorizes, they'll be redirected to your `redirect_uri` with a `code`:

```
http://localhost:4000/callback?code=abc123&state=xyz789
```

### Step 3: Exchange Code for Tokens

```javascript
const response = await fetch('http://localhost:3000/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    grant_type: 'authorization_code',
    code: 'abc123',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET',
    redirect_uri: 'http://localhost:4000/callback'
  })
});

const tokens = await response.json();
```

**Response:**
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

### Step 4: Get User Information

```javascript
const response = await fetch('http://localhost:3000/oauth/userinfo', {
  headers: {
    'Authorization': `Bearer ${access_token}`
  }
});

const userInfo = await response.json();
```

**Response:**
```json
{
  "sub": "user-id-123",
  "email": "user@example.com",
  "email_verified": true,
  "name": "John Doe",
  "given_name": "John",
  "family_name": "Doe"
}
```

### Step 5: Refresh Access Token

When the access token expires (after 1 hour by default):

```javascript
const response = await fetch('http://localhost:3000/oauth/token', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    grant_type: 'refresh_token',
    refresh_token: 'YOUR_REFRESH_TOKEN',
    client_id: 'YOUR_CLIENT_ID',
    client_secret: 'YOUR_CLIENT_SECRET'
  })
});

const { access_token } = await response.json();
```

---

## Direct Authentication

For trusted first-party applications, you can use direct authentication.

### Login

```javascript
const response = await fetch('http://localhost:3000/api/auth/login', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'user@example.com',
    password: 'password123'
  })
});

const data = await response.json();
```

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "refresh_token": "d2e4f6g8h0j2k4m6n8p0...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "user-id-123",
    "email": "user@example.com",
    "first_name": "John",
    "last_name": "Doe",
    "mfa_enabled": false
  }
}
```

### Register New User

```javascript
const response = await fetch('http://localhost:3000/api/auth/register', {
  method: 'POST',
  headers: {
    'Content-Type': 'application/json'
  },
  body: JSON.stringify({
    email: 'newuser@example.com',
    password: 'securePassword123',
    first_name: 'Jane',
    last_name: 'Smith'
  })
});
```

---

## Integration Examples

### Example 1: Node.js/Express Application

```javascript
const express = require('express');
const session = require('express-session');
const axios = require('axios');

const app = express();

app.use(session({
  secret: 'your-session-secret',
  resave: false,
  saveUninitialized: false
}));

const KS_URL = 'http://localhost:3000';
const CLIENT_ID = 'your_client_id';
const CLIENT_SECRET = 'your_client_secret';
const REDIRECT_URI = 'http://localhost:4000/callback';

// Login route - redirect to Konnect Service
app.get('/login', (req, res) => {
  const authUrl = new URL(`${KS_URL}/oauth/authorize`);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.append('scope', 'openid profile email');
  authUrl.searchParams.append('state', Math.random().toString(36));

  res.redirect(authUrl.toString());
});

// Callback route - handle OAuth callback
app.get('/callback', async (req, res) => {
  const { code } = req.query;

  try {
    // Exchange code for tokens
    const tokenResponse = await axios.post(`${KS_URL}/oauth/token`, {
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI
    });

    const { access_token, refresh_token } = tokenResponse.data;

    // Get user info
    const userResponse = await axios.get(`${KS_URL}/oauth/userinfo`, {
      headers: {
        Authorization: `Bearer ${access_token}`
      }
    });

    // Store in session
    req.session.user = userResponse.data;
    req.session.access_token = access_token;
    req.session.refresh_token = refresh_token;

    res.redirect('/dashboard');
  } catch (error) {
    console.error('Auth error:', error);
    res.redirect('/login');
  }
});

// Protected route
app.get('/dashboard', (req, res) => {
  if (!req.session.user) {
    return res.redirect('/login');
  }

  res.json({
    message: 'Welcome to your dashboard',
    user: req.session.user
  });
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy();
  res.redirect('/');
});

app.listen(4000, () => {
  console.log('App running on http://localhost:4000');
});
```

### Example 2: React Application

```javascript
// src/auth/KonnectAuth.js
import axios from 'axios';

const KS_URL = 'http://localhost:3000';
const CLIENT_ID = 'your_client_id';
const CLIENT_SECRET = 'your_client_secret';
const REDIRECT_URI = 'http://localhost:4000/callback';

export const login = () => {
  const authUrl = new URL(`${KS_URL}/oauth/authorize`);
  authUrl.searchParams.append('response_type', 'code');
  authUrl.searchParams.append('client_id', CLIENT_ID);
  authUrl.searchParams.append('redirect_uri', REDIRECT_URI);
  authUrl.searchParams.append('scope', 'openid profile email');
  authUrl.searchParams.append('state', Math.random().toString(36));

  window.location.href = authUrl.toString();
};

export const handleCallback = async (code) => {
  try {
    const response = await axios.post(`${KS_URL}/oauth/token`, {
      grant_type: 'authorization_code',
      code,
      client_id: CLIENT_ID,
      client_secret: CLIENT_SECRET,
      redirect_uri: REDIRECT_URI
    });

    const { access_token, refresh_token } = response.data;

    localStorage.setItem('access_token', access_token);
    localStorage.setItem('refresh_token', refresh_token);

    return true;
  } catch (error) {
    console.error('Auth error:', error);
    return false;
  }
};

export const getUserInfo = async () => {
  const token = localStorage.getItem('access_token');

  try {
    const response = await axios.get(`${KS_URL}/oauth/userinfo`, {
      headers: {
        Authorization: `Bearer ${token}`
      }
    });

    return response.data;
  } catch (error) {
    console.error('Failed to get user info:', error);
    return null;
  }
};

export const logout = () => {
  localStorage.removeItem('access_token');
  localStorage.removeItem('refresh_token');
};
```

```javascript
// src/components/Login.jsx
import { login } from '../auth/KonnectAuth';

function Login() {
  return (
    <div>
      <h1>Welcome</h1>
      <button onClick={login}>Login with Konnect Service</button>
    </div>
  );
}

export default Login;
```

```javascript
// src/components/Callback.jsx
import { useEffect } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import { handleCallback } from '../auth/KonnectAuth';

function Callback() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();

  useEffect(() => {
    const code = searchParams.get('code');

    if (code) {
      handleCallback(code).then(success => {
        if (success) {
          navigate('/dashboard');
        } else {
          navigate('/login');
        }
      });
    }
  }, [searchParams, navigate]);

  return <div>Loading...</div>;
}

export default Callback;
```

### Example 3: Python/Flask Application

```python
from flask import Flask, redirect, request, session, jsonify
import requests

app = Flask(__name__)
app.secret_key = 'your-secret-key'

KS_URL = 'http://localhost:3000'
CLIENT_ID = 'your_client_id'
CLIENT_SECRET = 'your_client_secret'
REDIRECT_URI = 'http://localhost:5000/callback'

@app.route('/login')
def login():
    auth_url = f"{KS_URL}/oauth/authorize"
    params = {
        'response_type': 'code',
        'client_id': CLIENT_ID,
        'redirect_uri': REDIRECT_URI,
        'scope': 'openid profile email',
        'state': 'random_state'
    }
    url = f"{auth_url}?{'&'.join([f'{k}={v}' for k, v in params.items()])}"
    return redirect(url)

@app.route('/callback')
def callback():
    code = request.args.get('code')

    # Exchange code for tokens
    token_response = requests.post(f"{KS_URL}/oauth/token", json={
        'grant_type': 'authorization_code',
        'code': code,
        'client_id': CLIENT_ID,
        'client_secret': CLIENT_SECRET,
        'redirect_uri': REDIRECT_URI
    })

    tokens = token_response.json()
    access_token = tokens['access_token']

    # Get user info
    user_response = requests.get(f"{KS_URL}/oauth/userinfo",
        headers={'Authorization': f"Bearer {access_token}"})

    session['user'] = user_response.json()
    session['access_token'] = access_token
    session['refresh_token'] = tokens['refresh_token']

    return redirect('/dashboard')

@app.route('/dashboard')
def dashboard():
    if 'user' not in session:
        return redirect('/login')

    return jsonify({
        'message': 'Welcome to your dashboard',
        'user': session['user']
    })

@app.route('/logout')
def logout():
    session.clear()
    return redirect('/')

if __name__ == '__main__':
    app.run(port=5000)
```

---

## Security Best Practices

1. **Always use HTTPS in production** - Never send credentials over HTTP
2. **Store client secrets securely** - Use environment variables, never commit to version control
3. **Implement state parameter** - Protects against CSRF attacks in OAuth flow
4. **Validate redirect URIs** - Only allow whitelisted redirect URIs
5. **Use short-lived access tokens** - Rely on refresh tokens for long sessions
6. **Implement token refresh logic** - Automatically refresh expired tokens
7. **Secure token storage** - Use httpOnly cookies or secure storage for tokens

---

## Testing Your Integration

1. Start Konnect Service:
   ```bash
   npm start
   ```

2. Register a test OAuth client via admin dashboard

3. Use the client credentials in your application

4. Test the full flow:
   - Login redirect
   - Authorization
   - Token exchange
   - User info retrieval
   - Token refresh
   - Logout

---

## Troubleshooting

### Common Issues

**Error: "Invalid client credentials"**
- Verify your `client_id` and `client_secret` are correct
- Check that the client is active in the database

**Error: "Invalid redirect_uri"**
- Ensure the redirect URI matches exactly what was registered
- Check for trailing slashes and protocol (http vs https)

**Error: "Invalid or expired token"**
- Implement token refresh logic
- Check token expiration times in .env

**Error: "CORS policy blocks request"**
- Update `FRONTEND_URL` in .env to match your app's URL
- Configure CORS properly for your domain

---

## Support

For issues or questions:
- Check the main [README.md](../README.md)
- Review API endpoints documentation
- Check server logs for detailed error messages
