# Konnect — Identity Provider Service

Custom OAuth2/OIDC-compliant Identity Provider with GraphQL API, built with Node.js, Express, PostgreSQL, Redis, and MinIO.

## Architecture

```
┌─────────────┐     ┌─────────────────────────────────────────────┐
│  3rd Party   │────▶│  Konnect API (:7300)                        │
│  Apps        │     │                                             │
│              │     │  /.well-known/openid-configuration          │
│              │     │  /oauth/authorize  /oauth/token             │
│              │     │  /oauth/userinfo   /oauth/revoke            │
│              │     │  /graphql (Apollo Server)                   │
└─────────────┘     └──────┬──────────┬──────────┬────────────────┘
                           │          │          │
                    ┌──────▼──┐  ┌────▼────┐  ┌─▼──────┐  ┌───────┐
                    │PostgreSQL│  │  Redis  │  │ MinIO  │  │Client │
                    │  (:7543) │  │ (:7637) │  │(:7900) │  │(:7517)│
                    └─────────┘  └─────────┘  └────────┘  └───────┘
```

## Quick Start (Development)

```bash
# 1. Start infrastructure
docker compose up -d postgres redis minio

# 2. Install dependencies
npm install

# 3. Generate RSA keys for JWT signing
npm run keys:generate

# 4. Create database tables
npm run db:migrate

# 5. Seed admin user + default OAuth client
npm run db:seed

# 6. Start API (auto-reload)
npm run dev

# 7. Start frontend (in another terminal)
cd client && npm install && npm run dev
```

**Default admin credentials:**
- Email: `admin@konnect.local`
- Password: `Admin123!`

**URLs:**
| Service             | URL                          |
|---------------------|------------------------------|
| API                 | http://localhost:7300         |
| GraphQL Playground  | http://localhost:7300/graphql |
| OIDC Discovery      | http://localhost:7300/.well-known/openid-configuration |
| Frontend            | http://localhost:7517         |
| MinIO Console       | http://localhost:7901         |

---

## Production Deployment

### Using Docker Compose

```bash
# Copy and edit production env
cp .env.production.example .env

# Start everything
docker compose up -d --build

# Run migrations + seed
docker compose exec api node src/database/migrate.js
docker compose exec api node src/database/seed.js
```

### Required Environment Variables (Production)

| Variable           | Description                          | Example                         |
|--------------------|--------------------------------------|---------------------------------|
| `NODE_ENV`         | Must be `production`                 | `production`                    |
| `API_PORT`         | API listen port                      | `7300`                          |
| `API_URL`          | Public URL of the API                | `https://auth.example.com`      |
| `CLIENT_URL`       | Public URL of the frontend           | `https://auth.example.com`      |
| `DB_HOST`          | PostgreSQL host                      | `postgres`                      |
| `DB_PORT`          | PostgreSQL port (internal)           | `5432`                          |
| `DB_NAME`          | Database name                        | `konnect`                       |
| `DB_USER`          | Database user                        | `konnect`                       |
| `DB_PASSWORD`      | **Strong** database password         | *(generate with `openssl rand -hex 32`)* |
| `REDIS_HOST`       | Redis host                           | `redis`                         |
| `REDIS_PORT`       | Redis port (internal)                | `6379`                          |
| `MINIO_ENDPOINT`   | MinIO host                           | `minio`                         |
| `MINIO_PORT`       | MinIO port (internal)                | `9000`                          |
| `MINIO_ACCESS_KEY` | MinIO access key                     | *(generate)*                    |
| `MINIO_SECRET_KEY` | MinIO secret key                     | *(generate)*                    |
| `MINIO_BUCKET`     | S3 bucket name                       | `konnect-files`                 |
| `MINIO_USE_SSL`    | `true` if behind HTTPS proxy         | `false`                         |
| `JWT_ISSUER`       | Must match `API_URL`                 | `https://auth.example.com`      |
| `JWT_ACCESS_TOKEN_TTL`  | Access token lifetime (seconds) | `900` (15min)                   |
| `JWT_REFRESH_TOKEN_TTL` | Refresh token lifetime (seconds)| `604800` (7 days)               |
| `SESSION_SECRET`   | **Strong** secret for sessions       | *(generate with `openssl rand -hex 32`)* |
| `ADMIN_EMAIL`      | Initial admin email                  | `admin@example.com`             |
| `ADMIN_PASSWORD`   | Initial admin password               | *(strong password)*             |

### GitHub Actions (Self-Hosted Runner)

The project includes a deploy workflow (`.github/workflows/deploy.yml`) that runs on a self-hosted runner labeled `ks-server`.

**GitHub Secrets to configure:**

```
DB_PASSWORD, MINIO_ACCESS_KEY, MINIO_SECRET_KEY,
SESSION_SECRET, ADMIN_EMAIL, ADMIN_PASSWORD,
API_URL, CLIENT_URL
```

Push to `main` triggers: build → deploy → migrate → seed.

---

## OAuth2 / OIDC Endpoints

| Endpoint                              | Method | Description                    |
|---------------------------------------|--------|--------------------------------|
| `/.well-known/openid-configuration`   | GET    | OIDC discovery document        |
| `/.well-known/jwks.json`              | GET    | Public keys (RS256)            |
| `/oauth/authorize`                    | GET    | Authorization code grant       |
| `/oauth/token`                        | POST   | Exchange code / refresh token  |
| `/oauth/userinfo`                     | GET    | OIDC standard claims           |
| `/oauth/revoke`                       | POST   | Revoke refresh token           |
| `/oauth/login`                        | POST   | Session login (consent flow)   |
| `/oauth/logout`                       | POST   | Session logout                 |
| `/graphql`                            | POST   | GraphQL API (Apollo Server)    |
| `/api/users/me/avatar`                | POST   | Upload avatar (multipart)      |
| `/health`                             | GET    | Health check                   |

### Supported Scopes

| Scope            | Claims returned                                                    |
|------------------|--------------------------------------------------------------------|
| `openid`         | `sub`                                                              |
| `profile`        | `name`, `given_name`, `family_name`, `preferred_username`, `picture`, `locale`, `zoneinfo` |
| `email`          | `email`, `email_verified`                                          |
| `phone`          | `phone_number`, `phone_number_verified`                            |
| `offline_access` | Issues a refresh token                                             |

### Supported Grant Types

- `authorization_code` (with optional PKCE via `S256`)
- `refresh_token` (with rotation + replay detection)

---

## Third-Party App Integration

### Step 1 — Register your app as an OAuth Client

**Via GraphQL** (requires admin token):
```graphql
mutation {
  createClient(input: {
    name: "My App"
    description: "My third-party application"
    redirect_uris: ["https://myapp.example.com/callback"]
    is_confidential: true
  }) {
    id
    client_id
    name
  }
}
```

**Via the admin UI:** Navigate to **OAuth Clients → + New Client**.

Save the returned `client_id` and `client_secret` — the secret is only shown once.

### Step 2 — Authorization Code Flow

```
1. Redirect user to:
   https://auth.example.com/oauth/authorize
     ?response_type=code
     &client_id=YOUR_CLIENT_ID
     &redirect_uri=https://myapp.example.com/callback
     &scope=openid profile email
     &state=RANDOM_STATE
     &code_challenge=BASE64URL_SHA256_OF_VERIFIER  (optional PKCE)
     &code_challenge_method=S256

2. User logs in and consents → redirected to:
   https://myapp.example.com/callback?code=AUTH_CODE&state=RANDOM_STATE

3. Exchange code for tokens:
   POST https://auth.example.com/oauth/token
   Content-Type: application/x-www-form-urlencoded

   grant_type=authorization_code
   &code=AUTH_CODE
   &redirect_uri=https://myapp.example.com/callback
   &client_id=YOUR_CLIENT_ID
   &client_secret=YOUR_CLIENT_SECRET        (confidential clients)
   &code_verifier=ORIGINAL_VERIFIER          (if PKCE used)

4. Response:
   {
     "access_token": "eyJ...",
     "token_type": "Bearer",
     "expires_in": 900,
     "refresh_token": "abc123...",
     "id_token": "eyJ..."
   }
```

### Step 3 — Use the Access Token

**OIDC UserInfo (standard claims):**
```bash
curl https://auth.example.com/oauth/userinfo \
  -H "Authorization: Bearer ACCESS_TOKEN"
```

**GraphQL (query exactly what you need):**
```bash
curl -X POST https://auth.example.com/graphql \
  -H "Authorization: Bearer ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "query": "{ me { id email first_name last_name roles { name } addresses { city country } } }"
  }'
```

Third parties can fetch only the fields they need — no over-fetching.

### Step 4 — Refresh Tokens

```bash
POST https://auth.example.com/oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=YOUR_CLIENT_ID
&client_secret=YOUR_CLIENT_SECRET
```

Returns a new `access_token` and rotated `refresh_token`. Old refresh tokens are automatically revoked (replay detection).

### Step 5 — Validate Tokens (in your app)

Use the JWKS endpoint to verify JWT signatures:
```
GET https://auth.example.com/.well-known/jwks.json
```

**Access token JWT payload:**
```json
{
  "sub": "user-uuid",
  "aud": "your-client-id",
  "scope": "openid profile email",
  "roles": ["user"],
  "email": "user@example.com",
  "username": "john",
  "iat": 1700000000,
  "exp": 1700000900,
  "iss": "https://auth.example.com"
}
```

### Integration Examples

<details>
<summary><b>Node.js / Express</b></summary>

```js
const jwt = require("jsonwebtoken");
const jwksClient = require("jwks-rsa");

const client = jwksClient({ jwksUri: "https://auth.example.com/.well-known/jwks.json" });

function getKey(header, callback) {
  client.getSigningKey(header.kid, (err, key) => {
    callback(err, key?.getPublicKey());
  });
}

function authMiddleware(req, res, next) {
  const token = req.headers.authorization?.replace("Bearer ", "");
  if (!token) return res.status(401).json({ error: "No token" });

  jwt.verify(token, getKey, { algorithms: ["RS256"], issuer: "https://auth.example.com" }, (err, decoded) => {
    if (err) return res.status(401).json({ error: "Invalid token" });
    req.user = decoded;
    next();
  });
}

app.get("/protected", authMiddleware, (req, res) => {
  res.json({ userId: req.user.sub, roles: req.user.roles });
});
```
</details>

<details>
<summary><b>PHP (Laravel / CodeIgniter)</b></summary>

```php
// Using firebase/php-jwt
use Firebase\JWT\JWT;
use Firebase\JWT\JWK;

$jwks = json_decode(file_get_contents('https://auth.example.com/.well-known/jwks.json'), true);
$keys = JWK::parseKeySet($jwks);

$token = str_replace('Bearer ', '', $_SERVER['HTTP_AUTHORIZATION'] ?? '');
$decoded = JWT::decode($token, $keys);

// $decoded->sub  = user ID
// $decoded->roles = ["user"]
// $decoded->email = "user@example.com"
```
</details>

<details>
<summary><b>Python (Flask / FastAPI)</b></summary>

```python
import jwt
import requests

JWKS_URL = "https://auth.example.com/.well-known/jwks.json"
jwks = requests.get(JWKS_URL).json()
public_keys = {}
for key_data in jwks["keys"]:
    kid = key_data["kid"]
    public_keys[kid] = jwt.algorithms.RSAAlgorithm.from_jwk(key_data)

def verify_token(token: str):
    header = jwt.get_unverified_header(token)
    key = public_keys[header["kid"]]
    return jwt.decode(token, key, algorithms=["RS256"],
                      issuer="https://auth.example.com")

# FastAPI dependency
from fastapi import Depends, HTTPException, Header

async def get_current_user(authorization: str = Header(...)):
    token = authorization.replace("Bearer ", "")
    try:
        return verify_token(token)
    except jwt.InvalidTokenError:
        raise HTTPException(401, "Invalid token")
```
</details>

<details>
<summary><b>React / SPA (frontend)</b></summary>

```js
// 1. Redirect to authorize
const params = new URLSearchParams({
  response_type: "code",
  client_id: "YOUR_CLIENT_ID",
  redirect_uri: "https://myapp.com/callback",
  scope: "openid profile email",
  state: crypto.randomUUID(),
});
window.location.href = `https://auth.example.com/oauth/authorize?${params}`;

// 2. On callback page, exchange code
const code = new URL(window.location).searchParams.get("code");
const res = await fetch("https://auth.example.com/oauth/token", {
  method: "POST",
  headers: { "Content-Type": "application/x-www-form-urlencoded" },
  body: new URLSearchParams({
    grant_type: "authorization_code",
    code,
    redirect_uri: "https://myapp.com/callback",
    client_id: "YOUR_CLIENT_ID",
  }),
});
const { access_token, refresh_token, id_token } = await res.json();
localStorage.setItem("access_token", access_token);

// 3. Query GraphQL for exactly what you need
const profile = await fetch("https://auth.example.com/graphql", {
  method: "POST",
  headers: {
    "Authorization": `Bearer ${access_token}`,
    "Content-Type": "application/json",
  },
  body: JSON.stringify({
    query: `{ me { id email first_name avatar_url } }`,
  }),
}).then(r => r.json());
```
</details>

---

## GraphQL API

### Available Queries

| Query          | Auth     | Description                    |
|----------------|----------|--------------------------------|
| `me`           | User     | Current user's profile         |
| `user(id)`     | Admin    | Get user by ID                 |
| `users(...)`   | Admin    | Paginated users with filters   |
| `role(id)`     | User     | Get role by ID                 |
| `roles`        | User     | List all roles                 |
| `permissions`  | User     | List all permissions           |
| `client(id)`   | Admin    | Get OAuth client by ID         |
| `clients(...)` | Admin    | Paginated OAuth clients list   |

### Available Mutations

| Mutation              | Auth  | Description                       |
|-----------------------|-------|-----------------------------------|
| `createUser`          | Admin | Create a new user                 |
| `updateUser`          | Self/Admin | Update user profile          |
| `deactivateUser`      | Admin | Disable a user account            |
| `addAddress`          | Self/Admin | Add address to user          |
| `removeAddress`       | Self/Admin | Remove an address            |
| `assignRole`          | Admin | Give a role to a user             |
| `revokeRole`          | Admin | Remove a role from a user         |
| `createRole`          | Admin | Create a new role                 |
| `deleteRole`          | Admin | Delete non-system role            |
| `assignPermission`    | Admin | Add permission to role            |
| `revokePermission`    | Admin | Remove permission from role       |
| `createClient`        | Admin | Register OAuth client             |
| `updateClient`        | Admin | Update OAuth client               |
| `revokeClient`        | Admin | Deactivate OAuth client           |

---

## Information Needed to Integrate

A third-party app developer needs:

1. **Konnect server URL** — e.g. `https://auth.example.com`
2. **Client ID** — obtained by registering their app
3. **Client Secret** — (confidential apps only, shown once at registration)
4. **Redirect URI(s)** — registered callback URL(s) for their app
5. **Scopes** — which data they need: `openid`, `profile`, `email`, `phone`, `offline_access`
6. **JWKS URL** — `https://auth.example.com/.well-known/jwks.json` for token validation

That's it. Everything else is auto-discoverable via:
```
GET https://auth.example.com/.well-known/openid-configuration
```

---

## Project Structure

```
konnect-service/
├── docker-compose.yml          # Infrastructure (PG, Redis, MinIO, API, Client)
├── Dockerfile                  # API container
├── package.json                # Backend dependencies
├── .env                        # Environment config (not committed)
├── .env.production.example     # Production env template
├── keys/                       # RSA keypair (auto-generated, not committed)
├── src/
│   ├── index.js                # Express bootstrap + Apollo Server
│   ├── config/
│   │   ├── index.js            # Centralized config from env
│   │   ├── database.js         # Sequelize connection
│   │   ├── keys.js             # RSA key generation + JWK
│   │   └── minio.js            # MinIO client + bucket init
│   ├── models/                 # Sequelize models
│   │   ├── User.js
│   │   ├── Address.js
│   │   ├── Role.js
│   │   ├── Permission.js
│   │   ├── OAuthClient.js
│   │   ├── AuthorizationCode.js
│   │   ├── RefreshToken.js
│   │   └── index.js            # Associations
│   ├── graphql/
│   │   ├── typeDefs.js         # GraphQL schema
│   │   ├── resolvers.js        # Query/mutation resolvers
│   │   └── index.js            # Apollo Server setup
│   ├── routes/
│   │   ├── oauth.js            # OAuth2/OIDC REST endpoints
│   │   └── users.js            # Avatar upload/delete
│   ├── middleware/
│   │   ├── auth.js             # authenticate, requireRole, requirePermission
│   │   └── errorHandler.js     # Global error handler
│   ├── services/
│   │   ├── tokenService.js     # JWT sign/verify, refresh rotation
│   │   └── storageService.js   # MinIO file operations
│   └── database/
│       ├── migrate.js          # Schema sync
│       └── seed.js             # Initial data
└── client/                     # React frontend (Vite)
    ├── Dockerfile              # Nginx production build
    ├── nginx.conf              # Reverse proxy to API
    ├── package.json
    ├── vite.config.js
    └── src/
        ├── App.jsx
        ├── main.jsx
        ├── context/AuthContext.jsx
        ├── graphql/
        │   ├── client.js       # Apollo Client setup
        │   └── queries.js      # GQL queries/mutations
        ├── components/Layout.jsx
        ├── pages/
        │   ├── LoginPage.jsx
        │   ├── CallbackPage.jsx
        │   ├── DashboardPage.jsx
        │   ├── ProfilePage.jsx
        │   ├── UsersPage.jsx
        │   ├── RolesPage.jsx
        │   └── ClientsPage.jsx
        └── styles/global.css
```

## License

Private — Internal use only.
