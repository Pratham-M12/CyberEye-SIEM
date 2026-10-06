// frontend/src/components/LoginView.jsx
import React, { useState } from 'react';
import { useAuth } from '../context/AuthContext';

export default function LoginView() {
  const { login, loading } = useAuth();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [errorMessage, setErrorMessage] = useState(null);
  const [serverError, setServerError] = useState(false);

  const handleSubmit = async (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setErrorMessage('Please enter both username and password.');
      return;
    }

    setErrorMessage(null);
    setServerError(false);

    try {
      await login(username.trim(), password);
    } catch (err) {
      if (err.response) {
        if (err.response.status === 429) {
          setErrorMessage(err.response.data?.error || 'Too many login attempts. Please wait 15 minutes.');
        } else if (err.response.status === 401) {
          // Generic authentication failure to prevent user enumeration
          setErrorMessage('Invalid username or password.');
        } else {
          setErrorMessage(err.response.data?.error || 'Authentication failed. Please try again.');
        }
      } else {
        // Network or server unreachable error
        setServerError(true);
        setErrorMessage('CyberEye SIEM server unreachable. Ensure backend is running.');
      }
    }
  };

  return (
    <div className="flex min-h-screen items-center justify-center bg-void px-4 py-12">
      <div className="w-full max-w-md space-y-8 rounded-panel border border-hairline bg-panel p-6 sm:p-8 shadow-2xl backdrop-blur">
        {/* CyberEye Branding Header */}
        <div className="text-center">
          <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-2xl bg-accent text-3xl font-extrabold text-white shadow-lg shadow-accent/25">
            C
          </div>
          <h2 className="mt-4 text-3xl font-bold tracking-tight text-white">
            CyberEye SIEM
          </h2>
          <p className="mt-2 text-sm text-ink-secondary">
            Enterprise Threat Detection &amp; Security Operations
          </p>
        </div>

        {/* Status / Alert Banner */}
        {errorMessage && (
          <div
            className={`rounded-lg border px-4 py-3 text-sm flex items-start gap-3 ${
              serverError
                ? 'border-yellow-600/40 bg-yellow-950/30 text-yellow-300'
                : 'border-red-500/30 bg-red-950/40 text-red-300'
            }`}
          >
            <svg
              className="h-5 w-5 flex-shrink-0 mt-0.5 text-current"
              fill="none"
              stroke="currentColor"
              viewBox="0 0 24 24"
            >
              <path
                strokeLinecap="round"
                strokeLinejoin="round"
                strokeWidth={2}
                d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z"
              />
            </svg>
            <div>
              <div className="font-semibold">
                {serverError ? 'Server Unavailable' : 'Authentication Error'}
              </div>
              <div>{errorMessage}</div>
            </div>
          </div>
        )}

        {/* Login Form */}
        <form className="mt-6 space-y-5" onSubmit={handleSubmit}>
          <div>
            <label
              htmlFor="username"
              className="block text-xs font-semibold uppercase tracking-wider text-ink-secondary"
            >
              Username
            </label>
            <div className="mt-2">
              <input
                id="username"
                name="username"
                type="text"
                autoComplete="username"
                required
                disabled={loading}
                value={username}
                onChange={(e) => {
                  setUsername(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="Enter operator username"
                className="w-full px-4 py-2.5 bg-raised text-white placeholder-ink-muted border border-hairline rounded-lg focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              />
            </div>
          </div>

          <div>
            <label
              htmlFor="password"
              className="block text-xs font-semibold uppercase tracking-wider text-ink-secondary"
            >
              Password
            </label>
            <div className="mt-2">
              <input
                id="password"
                name="password"
                type="password"
                autoComplete="current-password"
                required
                disabled={loading}
                value={password}
                onChange={(e) => {
                  setPassword(e.target.value);
                  if (errorMessage) setErrorMessage(null);
                }}
                placeholder="Enter password"
                className="w-full px-4 py-2.5 bg-raised text-white placeholder-ink-muted border border-hairline rounded-lg focus:outline-none focus:border-accent focus:ring-1 focus:ring-accent"
              />
            </div>
          </div>

          <div>
            <button
              type="submit"
              disabled={loading}
              className={`w-full flex items-center justify-center gap-2 rounded-lg bg-accent py-3 px-4 font-semibold text-white shadow-md transition hover:brightness-110 focus:outline-none ${
                loading ? 'cursor-not-allowed opacity-75' : ''
              }`}
            >
              {loading ? (
                <>
                  <svg
                    className="h-5 w-5 animate-spin text-white"
                    fill="none"
                    viewBox="0 0 24 24"
                  >
                    <circle
                      className="opacity-25"
                      cx="12"
                      cy="12"
                      r="10"
                      stroke="currentColor"
                      strokeWidth="4"
                    />
                    <path
                      className="opacity-75"
                      fill="currentColor"
                      d="M4 12a8 8 0 018-8v8H4z"
                    />
                  </svg>
                  <span>Verifying Credentials...</span>
                </>
              ) : (
                <span>Access Console</span>
              )}
            </button>
          </div>
        </form>

        <div className="pt-2 text-center text-xs text-ink-muted border-t border-hairline">
          CyberEye SIEM v1.0 • Authorized Personnel Only • Protected by RBAC
        </div>
      </div>
    </div>
  );
}
