import { useQuery, useMutation } from "@apollo/client";
import { useState } from "react";
import { CLIENTS_QUERY, CREATE_CLIENT, UPDATE_CLIENT, REVOKE_CLIENT } from "../graphql/queries";

export default function ClientsPage() {
  const [page, setPage] = useState(1);
  const { data, loading, refetch } = useQuery(CLIENTS_QUERY, { variables: { page, pageSize: 20 } });
  const [createClient] = useMutation(CREATE_CLIENT);
  const [updateClient] = useMutation(UPDATE_CLIENT);
  const [revokeClient] = useMutation(REVOKE_CLIENT);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [newSecret, setNewSecret] = useState(null);
  const [form, setForm] = useState({
    name: "",
    description: "",
    redirect_uris: "",
    is_confidential: true,
  });
  const [editForm, setEditForm] = useState({});

  const handleCreate = async (e) => {
    e.preventDefault();
    const input = {
      name: form.name,
      description: form.description,
      redirect_uris: form.redirect_uris.split("\n").map((u) => u.trim()).filter(Boolean),
      is_confidential: form.is_confidential,
    };
    const { data: result } = await createClient({ variables: { input } });
    setNewSecret(result?.createClient);
    setForm({ name: "", description: "", redirect_uris: "", is_confidential: true });
    setShowCreate(false);
    refetch();
  };

  const startEdit = (client) => {
    setEditing(client.id);
    setEditForm({
      name: client.name || "",
      description: client.description || "",
      redirect_uris: (client.redirect_uris || []).join("\n"),
      allowed_scopes: (client.allowed_scopes || []).join(", "),
    });
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    const input = {
      name: editForm.name,
      description: editForm.description,
      redirect_uris: editForm.redirect_uris.split("\n").map((u) => u.trim()).filter(Boolean),
      allowed_scopes: editForm.allowed_scopes.split(",").map((s) => s.trim()).filter(Boolean),
    };
    await updateClient({ variables: { id: editing, input } });
    setEditing(null);
    refetch();
  };

  const handleRevoke = async (id) => {
    if (!confirm("Revoke this client?")) return;
    await revokeClient({ variables: { id } });
    refetch();
  };

  if (loading) return <p>Loading…</p>;
  const clients = data?.clients;

  return (
    <div>
      <div className="page-header">
        <h1>OAuth Clients ({clients?.count || 0})</h1>
        <button className="btn btn-primary" onClick={() => { setShowCreate(!showCreate); setNewSecret(null); }}>
          {showCreate ? "Cancel" : "+ New Client"}
        </button>
      </div>

      {newSecret && (
        <div className="card alert alert-success">
          <h3>Client Created</h3>
          <p><strong>Client ID:</strong> <code>{newSecret.client_id}</code></p>
          <p className="hint">Save the client secret now — it won't be shown again.</p>
        </div>
      )}

      {showCreate && (
        <div className="card">
          <h3>Register OAuth Client</h3>
          <form onSubmit={handleCreate}>
            <div className="form-group">
              <label>Name</label>
              <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            </div>
            <div className="form-group">
              <label>Description</label>
              <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            </div>
            <div className="form-group">
              <label>Redirect URIs (one per line)</label>
              <textarea rows={3} required value={form.redirect_uris} onChange={(e) => setForm({ ...form, redirect_uris: e.target.value })} />
            </div>
            <div className="form-group">
              <label>
                <input type="checkbox" checked={form.is_confidential} onChange={(e) => setForm({ ...form, is_confidential: e.target.checked })} />
                {" "}Confidential client (has a secret)
              </label>
            </div>
            <button type="submit" className="btn btn-primary">Register</button>
          </form>
        </div>
      )}

      <table className="data-table">
        <thead>
          <tr>
            <th>Name</th>
            <th>Client ID</th>
            <th>Redirect URIs</th>
            <th>Scopes</th>
            <th>Status</th>
            <th>Actions</th>
          </tr>
        </thead>
        <tbody>
          {clients?.rows?.map((c) => (
            editing === c.id ? (
              <tr key={c.id} className="editing-row">
                <td colSpan={6}>
                  <form onSubmit={handleSaveEdit} className="edit-form">
                    <div className="form-row">
                      <div className="form-group">
                        <label>Name</label>
                        <input value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
                      </div>
                      <div className="form-group">
                        <label>Description</label>
                        <input value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} />
                      </div>
                    </div>
                    <div className="form-group">
                      <label>Redirect URIs (one per line)</label>
                      <textarea rows={3} value={editForm.redirect_uris} onChange={(e) => setEditForm({ ...editForm, redirect_uris: e.target.value })} />
                    </div>
                    <div className="form-group">
                      <label>Scopes (comma-separated)</label>
                      <input value={editForm.allowed_scopes} onChange={(e) => setEditForm({ ...editForm, allowed_scopes: e.target.value })} />
                    </div>
                    <div className="form-actions">
                      <button type="submit" className="btn btn-primary btn-sm">Save</button>
                      <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(null)}>Cancel</button>
                    </div>
                  </form>
                </td>
              </tr>
            ) : (
              <tr key={c.id}>
                <td><strong>{c.name}</strong><br /><small>{c.description}</small></td>
                <td><code>{c.client_id}</code></td>
                <td>{c.redirect_uris?.map((u, i) => <div key={i}><code>{u}</code></div>)}</td>
                <td>{c.allowed_scopes?.map((s) => <span key={s} className="badge badge-scope">{s}</span>)}</td>
                <td><span className={`status ${c.active ? "active" : "inactive"}`}>{c.active ? "Active" : "Revoked"}</span></td>
                <td>
                  <button className="btn btn-secondary btn-sm" onClick={() => startEdit(c)}>Edit</button>
                  {c.active && (
                    <button className="btn btn-danger btn-sm" onClick={() => handleRevoke(c.id)} style={{ marginLeft: 4 }}>Revoke</button>
                  )}
                </td>
              </tr>
            )
          ))}
        </tbody>
      </table>

      {clients && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button>
          <span>Page {page} / {Math.ceil(clients.count / clients.pageSize) || 1}</span>
          <button disabled={page * clients.pageSize >= clients.count} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      )}
    </div>
  );
}
