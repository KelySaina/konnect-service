import { Outlet, NavLink, useNavigate } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function Layout() {
  const { user, isAdmin, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate("/login");
  };

  return (
    <div className="layout">
      <aside className="sidebar">
        <div className="sidebar-header">
          <h2>Konnect</h2>
          <span className="subtitle">Identity Provider</span>
        </div>
        <nav>
          <NavLink to="/" end>Dashboard</NavLink>
          <NavLink to="/profile">Profile</NavLink>
          {isAdmin && (
            <>
              <hr />
              <span className="nav-section">Admin</span>
              <NavLink to="/users">Users</NavLink>
              <NavLink to="/roles">Roles</NavLink>
              <NavLink to="/clients">OAuth Clients</NavLink>
              <NavLink to="/organizations">Organizations</NavLink>
            </>
          )}
        </nav>
        <div className="sidebar-footer">
          <span className="user-info">{user?.email}</span>
          <button onClick={handleLogout} className="btn-logout">Logout</button>
        </div>
      </aside>
      <main className="content">
        <Outlet />
      </main>
    </div>
  );
}
