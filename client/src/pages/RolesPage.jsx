import { useQuery, useMutation } from "@apollo/client";
import { useState } from "react";
import {
  ROLES_QUERY, PERMISSIONS_QUERY,
  CREATE_ROLE, UPDATE_ROLE, DELETE_ROLE,
  ASSIGN_PERMISSION, REVOKE_PERMISSION,
} from "../graphql/queries";

export default function RolesPage() {
  const { data, loading, refetch } = useQuery(ROLES_QUERY);
  const { data: permsData } = useQuery(PERMISSIONS_QUERY);
  const [createRole] = useMutation(CREATE_ROLE);
  const [updateRole] = useMutation(UPDATE_ROLE);
  const [deleteRole] = useMutation(DELETE_ROLE);
  const [assignPermission] = useMutation(ASSIGN_PERMISSION);
  const [revokePermission] = useMutation(REVOKE_PERMISSION);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({ name: "", description: "" });
  const [editForm, setEditForm] = useState({ name: "", description: "" });

  const handleCreate = async (e) => {
    e.preventDefault();
    await createRole({ variables: { input: form } });
    setForm({ name: "", description: "" });
    setShowCreate(false);
    refetch();
  };

  const startEdit = (role) => {
    setEditing(role.id);
    setEditForm({ name: role.name, description: role.description || "" });
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    await updateRole({ variables: { id: editing, input: editForm } });
    setEditing(null);
    refetch();
  };

  const handleDelete = async (id) => {
    if (!confirm("Delete this role?")) return;
    await deleteRole({ variables: { id } });
    refetch();
  };

  const handleAssignPerm = async (roleId, permId) => {
    await assignPermission({ variables: { roleId, permissionId: permId } });
    refetch();
  };

  const handleRevokePerm = async (roleId, permId) => {
    await revokePermission({ variables: { roleId, permissionId: permId } });
    refetch();
  };

  if (loading) return <p>Loading…</p>;

  return (
    <div>
      <div className="page-header">
        <h1>Roles</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "Cancel" : "+ New Role"}
        </button>
      </div>

      {showCreate && (
        <div className="card">
          <h3>Create Role</h3>
          <form onSubmit={handleCreate} className="form-inline">
            <input placeholder="Name" required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
            <input placeholder="Description" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
            <button type="submit" className="btn btn-primary">Create</button>
          </form>
        </div>
      )}

      <div className="roles-grid">
        {data?.roles?.map((role) => (
          <div key={role.id} className="card">
            {editing === role.id ? (
              <form onSubmit={handleSaveEdit}>
                <div className="form-group">
                  <label>Name</label>
                  <input value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <input value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} />
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn btn-primary btn-sm">Save</button>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(null)}>Cancel</button>
                </div>
              </form>
            ) : (
              <>
                <div className="card-header">
                  <h3>{role.name}</h3>
                  <div>
                    <button className="btn btn-secondary btn-sm" onClick={() => startEdit(role)}>Edit</button>
                    {!role.is_system && (
                      <button className="btn btn-danger btn-sm" onClick={() => handleDelete(role.id)} style={{ marginLeft: 4 }}>Delete</button>
                    )}
                    {role.is_system && <span className="badge badge-system" style={{ marginLeft: 4 }}>System</span>}
                  </div>
                </div>
                <p>{role.description}</p>
              </>
            )}
            <div className="permissions-list">
              <strong>Permissions:</strong>
              {role.permissions?.length === 0 && <span className="hint"> None</span>}
              {role.permissions?.map((p) => (
                <span key={p.id} className="badge badge-perm">
                  {p.resource}:{p.action}
                  <button className="badge-remove" onClick={() => handleRevokePerm(role.id, p.id)} title="Remove">×</button>
                </span>
              ))}
              <select
                className="role-select"
                defaultValue=""
                onChange={(e) => { if (e.target.value) handleAssignPerm(role.id, e.target.value); e.target.value = ""; }}
              >
                <option value="" disabled>+ permission</option>
                {permsData?.permissions
                  ?.filter((p) => !role.permissions?.some((rp) => rp.id === p.id))
                  .map((p) => <option key={p.id} value={p.id}>{p.resource}:{p.action}</option>)}
              </select>
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}
