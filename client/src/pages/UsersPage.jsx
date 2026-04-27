import { useQuery, useMutation } from "@apollo/client";
import { useState } from "react";
import {
  USERS_QUERY, CREATE_USER, UPDATE_USER, DEACTIVATE_USER,
  ASSIGN_ROLE, REVOKE_ROLE, ROLES_QUERY,
} from "../graphql/queries";

export default function UsersPage() {
  const [page, setPage] = useState(1);
  const [search, setSearch] = useState("");
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);

  const { data, loading, refetch } = useQuery(USERS_QUERY, {
    variables: { page, pageSize: 20, filter: search ? { search } : {} },
  });
  const { data: rolesData } = useQuery(ROLES_QUERY);
  const [createUser] = useMutation(CREATE_USER);
  const [updateUser] = useMutation(UPDATE_USER);
  const [deactivateUser] = useMutation(DEACTIVATE_USER);
  const [assignRole] = useMutation(ASSIGN_ROLE);
  const [revokeRole] = useMutation(REVOKE_ROLE);

  const [form, setForm] = useState({ email: "", username: "", password: "", first_name: "", last_name: "" });
  const [editForm, setEditForm] = useState({});

  const handleCreate = async (e) => {
    e.preventDefault();
    await createUser({ variables: { input: form } });
    setForm({ email: "", username: "", password: "", first_name: "", last_name: "" });
    setShowCreate(false);
    refetch();
  };

  const startEdit = (user) => {
    setEditing(user.id);
    setEditForm({
      email: user.email || "",
      username: user.username || "",
      first_name: user.first_name || "",
      last_name: user.last_name || "",
      phone: user.phone || "",
      locale: user.locale || "fr",
      timezone: user.timezone || "Europe/Paris",
      active: user.active,
    });
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    await updateUser({ variables: { id: editing, input: editForm } });
    setEditing(null);
    refetch();
  };

  const handleDeactivate = async (id) => {
    if (!confirm("Deactivate this user?")) return;
    await deactivateUser({ variables: { id } });
    refetch();
  };

  const handleAssignRole = async (userId, roleId) => {
    await assignRole({ variables: { userId, roleId } });
    refetch();
  };

  const handleRevokeRole = async (userId, roleId) => {
    await revokeRole({ variables: { userId, roleId } });
    refetch();
  };

  if (loading) return <p>Loading…</p>;
  const users = data?.users;

  return (
    <div>
      <div className="page-header">
        <h1>Users ({users?.count || 0})</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "Cancel" : "+ New User"}
        </button>
      </div>

      <div className="search-bar">
        <input
          type="text"
          placeholder="Search by name, email…"
          value={search}
          onChange={(e) => { setSearch(e.target.value); setPage(1); }}
        />
      </div>

      {showCreate && (
        <div className="card">
          <h3>Create User</h3>
          <form onSubmit={handleCreate} className="form-inline">
            <input placeholder="Email" type="email" required value={form.email} onChange={(e) => setForm({ ...form, email: e.target.value })} />
            <input placeholder="Username" required value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })} />
            <input placeholder="Password" type="password" required value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })} />
            <input placeholder="First name" value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
            <input placeholder="Last name" value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
            <button type="submit" className="btn btn-primary">Create</button>
          </form>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>Username</th>
            <th>Email</th>
            <th>Name</th>
            <th>Roles</th>
            <th>Status</th>
            <th>Created</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {users?.rows?.map((u) => (
            editing === u.id ? (
              <tr key={u.id} className="editing-row">
                <td colSpan={7}>
                  <form onSubmit={handleSaveEdit} className="edit-form">
                    <div className="form-row">
                      <div className="form-group">
                        <label>Email</label>
                        <input value={editForm.email} onChange={(e) => setEditForm({ ...editForm, email: e.target.value })} />
                      </div>
                      <div className="form-group">
                        <label>Username</label>
                        <input value={editForm.username} onChange={(e) => setEditForm({ ...editForm, username: e.target.value })} />
                      </div>
                      <div className="form-group">
                        <label>First name</label>
                        <input value={editForm.first_name} onChange={(e) => setEditForm({ ...editForm, first_name: e.target.value })} />
                      </div>
                      <div className="form-group">
                        <label>Last name</label>
                        <input value={editForm.last_name} onChange={(e) => setEditForm({ ...editForm, last_name: e.target.value })} />
                      </div>
                    </div>
                    <div className="form-row">
                      <div className="form-group">
                        <label>Phone</label>
                        <input value={editForm.phone} onChange={(e) => setEditForm({ ...editForm, phone: e.target.value })} />
                      </div>
                      <div className="form-group">
                        <label>Locale</label>
                        <select value={editForm.locale} onChange={(e) => setEditForm({ ...editForm, locale: e.target.value })}>
                          <option value="fr">Français</option>
                          <option value="en">English</option>
                          <option value="de">Deutsch</option>
                          <option value="es">Español</option>
                        </select>
                      </div>
                      <div className="form-group">
                        <label>Active</label>
                        <select value={editForm.active ? "true" : "false"} onChange={(e) => setEditForm({ ...editForm, active: e.target.value === "true" })}>
                          <option value="true">Active</option>
                          <option value="false">Inactive</option>
                        </select>
                      </div>
                    </div>
                    <div className="form-actions">
                      <button type="submit" className="btn btn-primary btn-sm">Save</button>
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(null)}>Cancel</button>
                    </div>
                  </form>
                </td>
              </tr>
            ) : (
              <tr key={u.id}>
                <td>{u.username}</td>
                <td>{u.email}</td>
                <td>{[u.first_name, u.last_name].filter(Boolean).join(" ")}</td>
                <td>
                  {u.roles?.map((r) => (
                    <span key={r.id} className="badge">
                      {r.name}
                      <button className="badge-remove" onClick={() => handleRevokeRole(u.id, r.id)} title="Remove role">×</button>
                    </span>
                  ))}
                  <select
                    className="role-select"
                    defaultValue=""
                    onChange={(e) => { if (e.target.value) handleAssignRole(u.id, e.target.value); e.target.value = ""; }}
                  >
                    <option value="" disabled>+ role</option>
                    {rolesData?.roles
                      ?.filter((r) => !u.roles?.some((ur) => ur.id === r.id))
                      .map((r) => <option key={r.id} value={r.id}>{r.name}</option>)}
                  </select>
                </td>
                <td><span className={`status ${u.active ? "active" : "inactive"}`}>{u.active ? "Active" : "Inactive"}</span></td>
                <td>{new Date(u.createdAt).toLocaleDateString("fr")}</td>
                <td>
                  <button className="btn btn-secondary btn-sm" onClick={() => startEdit(u)}>Edit</button>
                  {u.active && (
                    <button className="btn btn-danger btn-sm" onClick={() => handleDeactivate(u.id)} style={{ marginLeft: 4 }}>Deactivate</button>
                  )}
                </td>
              </tr>
            )
          ))}
        </tbody>
      </table>

      {users && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button>
          <span>Page {page} / {Math.ceil(users.count / users.pageSize) || 1}</span>
          <button disabled={page * users.pageSize >= users.count} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      )}
    </div>
  );
}
