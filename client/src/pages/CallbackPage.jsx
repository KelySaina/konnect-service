import { useEffect, useRef, useState } from "react";
import { useNavigate, useSearchParams } from "react-router-dom";
import { useAuth } from "../context/AuthContext";

export default function CallbackPage() {
  const [params] = useSearchParams();
  const { loginWithToken } = useAuth();
  const navigate = useNavigate();
  const [error, setError] = useState("");
  const exchanged = useRef(false);

  useEffect(() => {
    // Guard against React StrictMode double-mount
    if (exchanged.current) return;
    exchanged.current = true;

    const code = params.get("code");
    if (!code) {
      setError("No authorization code received");
      return;
    }

    const exchange = async () => {
      try {
        const res = await fetch("/oauth/token", {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            grant_type: "authorization_code",
            code,
            redirect_uri: `${window.location.origin}/callback`,
            client_id: "konnect-webapp",
          }),
        });

        if (!res.ok) {
          const data = await res.json();
          throw new Error(data.error_description || data.error || "Token exchange failed");
        }

        const data = await res.json();
        loginWithToken(data.access_token, data.refresh_token);
        navigate("/");
      } catch (err) {
        setError(err.message);
      }
    };

    exchange();
  }, [params, loginWithToken, navigate]);

  if (error) {
    return (
      <div className="login-page">
        <div className="login-card">
          <h2>Authentication Error</h2>
          <div className="alert alert-error">{error}</div>
          <a href="/login">Back to login</a>
        </div>
      </div>
    );
  }

  return (
    <div className="login-page">
      <div className="login-card">
        <p>Completing authentication…</p>
      </div>
    </div>
  );
}
