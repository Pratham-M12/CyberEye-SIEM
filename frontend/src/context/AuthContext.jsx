// frontend/src/context/AuthContext.jsx
import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { loginApi, logoutApi, setAuthToken, setOnUnauthorized } from '../api/siem';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  // In accordance with Phase 7C security requirements, the access token is stored
  // strictly in React memory (not persisted in localStorage or sessionStorage) to eliminate
  // persistent token theft risks via XSS. Browser reloads require re-authenticating.
  const [token, setToken] = useState(null);
  const [user, setUser] = useState(null);
  const [loading, setLoading] = useState(false);

  const logout = useCallback(async () => {
    try {
      if (token) {
        await logoutApi().catch(() => {});
      }
    } finally {
      setToken(null);
      setUser(null);
      setAuthToken(null);
    }
  }, [token]);

  useEffect(() => {
    // When an authenticated API call receives HTTP 401 Unauthorized, automatically log out
    setOnUnauthorized(() => {
      setToken(null);
      setUser(null);
      setAuthToken(null);
    });
  }, []);

  const login = async (username, password) => {
    setLoading(true);
    try {
      const data = await loginApi(username, password);
      setToken(data.token);
      setUser(data.user);
      setAuthToken(data.token);
      return data.user;
    } finally {
      setLoading(false);
    }
  };

  /**
   * Helper to evaluate RBAC role permissions for the current user.
   * Usage: hasRole('admin') or hasRole('admin', 'analyst')
   */
  const hasRole = (...roles) => {
    if (!user || !user.role) return false;
    const normalized = roles.flat().map((r) => String(r).toLowerCase());
    return normalized.includes(user.role.toLowerCase());
  };

  const value = {
    user,
    token,
    isAuthenticated: Boolean(token && user),
    loading,
    login,
    logout,
    hasRole,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    throw new Error('useAuth must be used within an AuthProvider');
  }
  return context;
}
