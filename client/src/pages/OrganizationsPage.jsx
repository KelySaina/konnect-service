import { useQuery, useMutation } from "@apollo/client";
import { useState } from "react";
import {
  ORGANIZATIONS_QUERY, USERS_QUERY,
  CREATE_ORGANIZATION, UPDATE_ORGANIZATION,
  ADD_ORG_MEMBER, REMOVE_ORG_MEMBER,
} from "../graphql/queries";

export default function OrganizationsPage() {
  const [page, setPage] = useState(1);
  const { data, loading, refetch } = useQuery(ORGANIZATIONS_QUERY, { variables: { page, pageSize: 20 } });
  const { data: usersData } = useQuery(USERS_QUERY, { variables: { page: 1, pageSize: 100 } });
  const [createOrganization] = useMutation(CREATE_ORGANIZATION);
  const [updateOrganization] = useMutation(UPDATE_ORGANIZATION);
  const [addMember] = useMutation(ADD_ORG_MEMBER);
  const [removeMember] = useMutation(REMOVE_ORG_MEMBER);
  const [showCreate, setShowCreate] = useState(false);
  const [editing, setEditing] = useState(null);
  const [form, setForm] = useState({ name: "", slug: "", description: "", domain: "" });
  const [editForm, setEditForm] = useState({});

  const handleCreate = async (e) => {
    e.preventDefault();
    await createOrganization({ variables: { input: form } });
    setForm({ name: "", slug: "", description: "", domain: "" });
    setShowCreate(false);
    refetch();
  };

  const startEdit = (org) => {
    setEditing(org.id);
    setEditForm({
      name: org.name || "",
      description: org.description || "",
      domain: org.domain || "",
      active: org.active,
    });
  };

  const handleSaveEdit = async (e) => {
    e.preventDefault();
    await updateOrganization({ variables: { id: editing, input: editForm } });
    setEditing(null);
    refetch();
  };

  const handleAddMember = async (orgId, userId) => {
    await addMember({ variables: { organizationId: orgId, userId } });
    refetch();
  };

  const handleRemoveMember = async (orgId, userId) => {
    await removeMember({ variables: { organizationId: orgId, userId } });
    refetch();
  };

  if (loading) return <p>Loading…</p>;
  const orgs = data?.organizations;

  return (
    <div>
      <div className="page-header">
        <h1>Organizations ({orgs?.count || 0})</h1>
        <button className="btn btn-primary" onClick={() => setShowCreate(!showCreate)}>
          {showCreate ? "Cancel" : "+ New Organization"}
        </button>
      </div>

      {showCreate && (
        <div className="card">
          <h3>Create Organization</h3>
          <form onSubmit={handleCreate}>
            <div className="form-row">
              <div className="form-group">
                <label>Name</label>
                <input required value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Slug</label>
                <input required value={form.slug} placeholder="my-org" onChange={(e) => setForm({ ...form, slug: e.target.value })} />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group">
                <label>Description</label>
                <input value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
              </div>
              <div className="form-group">
                <label>Domain (auto-join)</label>
                <input placeholder="company.com" value={form.domain} onChange={(e) => setForm({ ...form, domain: e.target.value })} />
              </div>
            </div>
            <button type="submit" className="btn btn-primary">Create</button>
          </form>
        </div>
      )}

      <div className="roles-grid">
        {orgs?.rows?.map((org) => (
          <div key={org.id} className="card">
            {editing === org.id ? (
              <form onSubmit={handleSaveEdit}>
                <div className="form-group">
                  <label>Name</label>
                  <input value={editForm.name} onChange={(e) => setEditForm({ ...editForm, name: e.target.value })} />
                </div>
                <div className="form-group">
                  <label>Description</label>
                  <input value={editForm.description} onChange={(e) => setEditForm({ ...editForm, description: e.target.value })} />
                </div>
                <div className="form-group">
                  <label>Domain</label>
                  <input value={editForm.domain} onChange={(e) => setEditForm({ ...editForm, domain: e.target.value })} />
                </div>
                <div className="form-group">
                  <label>Active</label>
                  <select value={editForm.active ? "true" : "false"} onChange={(e) => setEditForm({ ...editForm, active: e.target.value === "true" })}>
                    <option value="true">Active</option>
                    <option value="false">Inactive</option>
                  </select>
                </div>
                <div className="form-actions">
                  <button type="submit" className="btn btn-primary btn-sm">Save</button>
                  <button type="button" className="btn btn-secondary btn-sm" onClick={() => setEditing(null)}>Cancel</button>
                </div>
              </form>
            ) : (
              <>
                <div className="card-header">
                  <div>
                    <h3>{org.name}</h3>
                    <small className="hint">{org.slug}{org.domain ? ` · ${org.domain}` : ""}</small>
                  </div>
                  <div>
                    <button className="btn btn-secondary btn-sm" onClick={() => startEdit(org)}>Edit</button>
                    <span className={`status ${org.active ? "active" : "inactive"}`} style={{ marginLeft: 8 }}>
                      {org.active ? "Active" : "Inactive"}
                    </span>
                  </div>
                </div>
                <p>{org.description}</p>
              </>
            )}
            <div className="permissions-list">
              <strong>Members ({org.members?.length || 0}):</strong>
              {org.members?.map((m) => (
                <span key={m.id} className="badge">
                  {m.username || m.email}
                  <button className="badge-remove" onClick={() => handleRemoveMember(org.id, m.id)} title="Remove">×</button>
                </span>
              ))}
              <select
                className="role-select"
                defaultValue=""
                onChange={(e) => { if (e.target.value) handleAddMember(org.id, e.target.value); e.target.value = ""; }}
              >
                <option value="" disabled>+ member</option>
                {usersData?.users?.rows
                  ?.filter((u) => !org.members?.some((m) => m.id === u.id))
                  .map((u) => <option key={u.id} value={u.id}>{u.username} ({u.email})</option>)}
              </select>
            </div>
          </div>
        ))}
      </div>

      {orgs && (
        <div className="pagination">
          <button disabled={page <= 1} onClick={() => setPage(page - 1)}>← Previous</button>
          <span>Page {page} / {Math.ceil(orgs.count / orgs.pageSize) || 1}</span>
          <button disabled={page * orgs.pageSize >= orgs.count} onClick={() => setPage(page + 1)}>Next →</button>
        </div>
      )}
    </div>
  );
}
