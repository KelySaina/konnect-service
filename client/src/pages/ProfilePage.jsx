import { useState } from "react";
import { useMutation } from "@apollo/client";
import { useAuth } from "../context/AuthContext";
import { UPDATE_USER } from "../graphql/queries";

export default function ProfilePage() {
  const { user, fetchUser } = useAuth();
  const [updateUser] = useMutation(UPDATE_USER);
  const [form, setForm] = useState({
    first_name: user?.first_name || "",
    last_name: user?.last_name || "",
    phone: user?.phone || "",
    locale: user?.locale || "fr",
    timezone: user?.timezone || "Europe/Paris",
  });
  const [saved, setSaved] = useState(false);
  const [avatarUploading, setAvatarUploading] = useState(false);

  const handleSave = async (e) => {
    e.preventDefault();
    await updateUser({ variables: { id: user.id, input: form } });
    await fetchUser();
    setSaved(true);
    setTimeout(() => setSaved(false), 2000);
  };

  const handleAvatarUpload = async (e) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setAvatarUploading(true);
    const formData = new FormData();
    formData.append("avatar", file);
    const token = localStorage.getItem("access_token");
    await fetch("/api/users/me/avatar", {
      method: "POST",
      headers: { Authorization: `Bearer ${token}` },
      body: formData,
    });
    await fetchUser();
    setAvatarUploading(false);
  };

  return (
    <div>
      <h1>Profile</h1>

      <div className="card profile-card">
        <div className="avatar-section">
          <div className="avatar">
            {user?.avatar_url ? (
              <img src={user.avatar_url} alt="Avatar" />
            ) : (
              <div className="avatar-placeholder">{user?.first_name?.[0] || user?.username?.[0] || "?"}</div>
            )}
          </div>
          <label className="btn btn-secondary btn-sm">
            {avatarUploading ? "Uploading…" : "Change avatar"}
            <input type="file" accept="image/*" hidden onChange={handleAvatarUpload} />
          </label>
        </div>

        <form onSubmit={handleSave}>
          <div className="form-row">
            <div className="form-group">
              <label>First name</label>
              <input value={form.first_name} onChange={(e) => setForm({ ...form, first_name: e.target.value })} />
            </div>
            <div className="form-group">
              <label>Last name</label>
              <input value={form.last_name} onChange={(e) => setForm({ ...form, last_name: e.target.value })} />
            </div>
          </div>
          <div className="form-group">
            <label>Email</label>
            <input value={user?.email || ""} disabled />
          </div>
          <div className="form-group">
            <label>Phone</label>
            <input value={form.phone} onChange={(e) => setForm({ ...form, phone: e.target.value })} />
          </div>
          <div className="form-row">
            <div className="form-group">
              <label>Locale</label>
              <select value={form.locale} onChange={(e) => setForm({ ...form, locale: e.target.value })}>
                <option value="fr">Français</option>
                <option value="en">English</option>
                <option value="de">Deutsch</option>
                <option value="es">Español</option>
              </select>
            </div>
            <div className="form-group">
              <label>Timezone</label>
              <input value={form.timezone} onChange={(e) => setForm({ ...form, timezone: e.target.value })} />
            </div>
          </div>
          <button type="submit" className="btn btn-primary">Save changes</button>
          {saved && <span className="save-notice">✓ Saved</span>}
        </form>
      </div>

      <div className="card">
        <h3>Addresses</h3>
        {user?.addresses?.length === 0 && <p className="hint">No addresses yet.</p>}
        {user?.addresses?.map((a) => (
          <div key={a.id} className="address-item">
            <span className="badge">{a.label}</span>
            {[a.street, a.postal_code, a.city, a.country].filter(Boolean).join(", ")}
            {a.is_primary && <span className="badge badge-system">Primary</span>}
          </div>
        ))}
      </div>

      <div className="card">
        <h3>Security Info</h3>
        <p>User ID: <code>{user?.id}</code></p>
        <p>Email verified: {user?.email_verified ? "Yes" : "No"}</p>
        <p>Last login: {user?.last_login_at ? new Date(user.last_login_at).toLocaleString("fr") : "Never"}</p>
        <p>Roles: {user?.roles?.map((r) => r.name).join(", ") || "None"}</p>
      </div>
    </div>
  );
}
