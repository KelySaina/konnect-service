import { useAuth } from "../context/AuthContext";

export default function DashboardPage() {
  const { user, isAdmin } = useAuth();

  return (
    <div>
      <h1>Dashboard</h1>
      <div className="card">
        <h3>Welcome, {user?.first_name || user?.username}</h3>
        <p>Email: {user?.email}</p>
        <p>Roles: {user?.roles?.map((r) => r.name).join(", ") || "none"}</p>
        {isAdmin && (
          <div className="stats">
            <p className="hint">Use the sidebar to manage users, roles, and OAuth clients.</p>
          </div>
        )}
      </div>

      <div className="card">
        <h3>OIDC Endpoints</h3>
        <table>
          <tbody>
            <tr>
              <td>Discovery</td>
              <td><code>/.well-known/openid-configuration</code></td>
            </tr>
            <tr>
              <td>JWKS</td>
              <td><code>/.well-known/jwks.json</code></td>
            </tr>
            <tr>
              <td>Authorize</td>
              <td><code>/oauth/authorize</code></td>
            </tr>
            <tr>
              <td>Token</td>
              <td><code>/oauth/token</code></td>
            </tr>
            <tr>
              <td>UserInfo</td>
              <td><code>/oauth/userinfo</code></td>
            </tr>
            <tr>
              <td>GraphQL</td>
              <td><code>/graphql</code></td>
            </tr>
          </tbody>
        </table>
      </div>
    </div>
  );
}
