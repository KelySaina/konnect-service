import { createContext, useContext, useState, useEffect, useCallback } from "react";
import { client as apolloClient } from "../graphql/client";
import { ME_QUERY } from "../graphql/queries";

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(true);
  const token = localStorage.getItem("access_token");

  const fetchUser = useCallback(async () => {
    if (!token) {
      setLoading(false);
      return;
    }
    try {
      const { data } = await apolloClient.query({ query: ME_QUERY, fetchPolicy: "network-only" });
      setUser(data.me);
    } catch {
      localStorage.removeItem("access_token");
      localStorage.removeItem("refresh_token");
      setUser(null);
    }
    setLoading(false);
  }, [token]);

  useEffect(() => {
    fetchUser();
  }, [fetchUser]);

  const login = async (email, password) => {
    const res = await fetch("/oauth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      credentials: "include",
      body: JSON.stringify({ email, password }),
    });
    if (!res.ok) {
      const err = await res.json();
      throw new Error(err.error || "Login failed");
    }

    // After session login, get tokens via auth code flow for the built-in client
    // For the admin UI we use a direct token approach
    const tokenRes = await fetch("/oauth/token", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: new URLSearchParams({
        grant_type: "authorization_code_direct",
        email,
        password,
      }),
    });

    // Fallback: use session-based auth and fetch user profile
    await fetchUser();
    return user;
  };

  const loginWithToken = (accessToken, refreshToken) => {
    localStorage.setItem("access_token", accessToken);
    if (refreshToken) localStorage.setItem("refresh_token", refreshToken);
    fetchUser();
  };

  const logout = async () => {
    await fetch("/oauth/logout", { method: "POST", credentials: "include" });
    localStorage.removeItem("access_token");
    localStorage.removeItem("refresh_token");
    setUser(null);
    apolloClient.clearStore();
  };

  const isAdmin = user?.roles?.some((r) => r.name === "admin") ?? false;

  return (
    <AuthContext.Provider value={{ user, loading, login, loginWithToken, logout, isAdmin, fetchUser }}>
      {children}
    </AuthContext.Provider>
  );
}

export function useAuth() {
  const ctx = useContext(AuthContext);
  if (!ctx) throw new Error("useAuth must be used within AuthProvider");
  return ctx;
}
