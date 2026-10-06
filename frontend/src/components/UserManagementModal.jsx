// frontend/src/components/UserManagementModal.jsx
import React, { useState, useEffect } from 'react';
import { getUsers, createUserApi, updateUserApi, deleteUserApi } from '../api/siem';

export default function UserManagementModal({ isOpen, onClose, currentUsername }) {
  const [users, setUsers] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [success, setSuccess] = useState(null);

  // New user form state
  const [newUsername, setNewUsername] = useState('');
  const [newPassword, setNewPassword] = useState('');
  const [newRole, setNewRole] = useState('analyst');
  const [creating, setCreating] = useState(false);

  // Password reset inline state: userId -> newPassword
  const [passwordResetUserId, setPasswordResetUserId] = useState(null);
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [updatingPassword, setUpdatingPassword] = useState(false);

  const fetchUsersList = async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await getUsers();
      setUsers(data.users || []);
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to fetch user accounts');
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    if (isOpen) {
      fetchUsersList();
      setError(null);
      setSuccess(null);
    }
  }, [isOpen]);

  if (!isOpen) return null;

  const handleCreateUser = async (e) => {
    e.preventDefault();
    setError(null);
    setSuccess(null);

    if (!newUsername.trim() || newPassword.length < 8) {
      setError('Username required and password must be at least 8 characters long.');
      return;
    }

    setCreating(true);
    try {
      await createUserApi({
        username: newUsername.trim(),
        password: newPassword,
        role: newRole,
      });
      setSuccess(`User "${newUsername.trim()}" created successfully.`);
      setNewUsername('');
      setNewPassword('');
      setNewRole('analyst');
      await fetchUsersList();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to create user account.');
    } finally {
      setCreating(false);
    }
  };

  const handleRoleChange = async (userId, targetRole) => {
    setError(null);
    setSuccess(null);
    try {
      await updateUserApi(userId, { role: targetRole });
      setSuccess(`Updated role to ${targetRole.toUpperCase()}`);
      await fetchUsersList();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to update user role');
    }
  };

  const handleToggleActive = async (user) => {
    setError(null);
    setSuccess(null);
    const newStatus = !user.isActive;
    try {
      await updateUserApi(user.id, { isActive: newStatus });
      setSuccess(`User "${user.username}" ${newStatus ? 'activated' : 'deactivated'}.`);
      await fetchUsersList();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to modify account status');
    }
  };

  const handleResetPasswordSubmit = async (userId) => {
    if (resetPasswordValue.length < 8) {
      setError('Password must be at least 8 characters long.');
      return;
    }

    setUpdatingPassword(true);
    setError(null);
    setSuccess(null);
    try {
      await updateUserApi(userId, { password: resetPasswordValue });
      setSuccess('Password updated successfully.');
      setPasswordResetUserId(null);
      setResetPasswordValue('');
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to reset user password.');
    } finally {
      setUpdatingPassword(false);
    }
  };

  const handleDeleteUser = async (user) => {
    if (!window.confirm(`Are you sure you want to permanently delete user "${user.username}"?`)) {
      return;
    }
    setError(null);
    setSuccess(null);
    try {
      await deleteUserApi(user.id);
      setSuccess(`User "${user.username}" removed.`);
      await fetchUsersList();
    } catch (err) {
      setError(err.response?.data?.error || 'Failed to delete user.');
    }
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-3 sm:p-4 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-label="User Management and RBAC"
    >
      <div className="relative w-full max-w-4xl rounded-panel border border-hairline bg-panel p-4 sm:p-6 shadow-2xl space-y-6">
        {/* Modal Header */}
        <div className="flex items-center justify-between border-b border-hairline pb-4">
          <div className="flex items-center gap-3">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-accent text-white font-bold">
              U
            </div>
            <div>
              <h2 className="text-xl font-bold text-white">User Management &amp; RBAC</h2>
              <p className="text-xs text-ink-secondary">
                Admin Console • Manage Operator Accounts &amp; Access Roles
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            aria-label="Close user management dialog"
            className="rounded-lg p-2 text-ink-secondary hover:bg-raised hover:text-white transition"
          >
            ✕
          </button>
        </div>

        {/* Status Alerts */}
        {error && (
          <div className="rounded-lg border border-red-500/40 bg-red-950/40 p-3 text-sm text-red-300">
            {error}
          </div>
        )}
        {success && (
          <div className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3 text-sm text-emerald-300">
            {success}
          </div>
        )}

        {/* Create User Section */}
        <div className="rounded-lg border border-hairline bg-raised p-4">
          <h3 className="text-sm font-semibold uppercase tracking-wider text-white mb-3">
            Provision New User Account
          </h3>
          <form onSubmit={handleCreateUser} className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Username</label>
              <input
                type="text"
                placeholder="operator_name"
                value={newUsername}
                onChange={(e) => setNewUsername(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Password (min 8 chars)</label>
              <input
                type="password"
                placeholder="••••••••"
                value={newPassword}
                onChange={(e) => setNewPassword(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white"
                required
              />
            </div>
            <div>
              <label className="block text-xs text-ink-secondary mb-1">Role</label>
              <select
                value={newRole}
                onChange={(e) => setNewRole(e.target.value)}
                className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white"
              >
                <option value="analyst">Analyst</option>
                <option value="read_only">Read-Only</option>
                <option value="admin">Administrator</option>
              </select>
            </div>
            <div className="flex items-end">
              <button
                type="submit"
                disabled={creating}
                className="w-full py-2 px-4 rounded bg-accent hover:brightness-110 text-white font-medium text-sm transition"
              >
                {creating ? 'Creating...' : '+ Add User'}
              </button>
            </div>
          </form>
        </div>

        {/* Existing Users Table */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <h3 className="text-sm font-semibold uppercase tracking-wider text-white">
              System Operators ({users.length})
            </h3>
            {loading && <span className="text-xs text-ink-muted">Refreshing list...</span>}
          </div>

          <div className="overflow-x-auto rounded-lg border border-hairline">
            <table className="w-full text-left text-sm text-ink-secondary">
              <thead className="bg-raised text-xs uppercase tracking-wider text-ink-muted border-b border-hairline">
                <tr>
                  <th className="px-4 py-3">Username</th>
                  <th className="px-4 py-3">Role</th>
                  <th className="px-4 py-3">Status</th>
                  <th className="px-4 py-3">Created</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-hairline">
                {users.map((u) => {
                  const isCurrent = u.username === currentUsername;
                  const isResetting = passwordResetUserId === u.id;

                  return (
                    <React.Fragment key={u.id}>
                      <tr className="hover:bg-raised/50 transition">
                        <td className="px-4 py-3 font-medium text-white flex items-center gap-2">
                          {u.username}
                          {isCurrent && (
                            <span className="text-[10px] uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
                              You
                            </span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <select
                            value={u.role}
                            onChange={(e) => handleRoleChange(u.id, e.target.value)}
                            className="text-xs px-2 py-1 bg-panel border border-hairline rounded text-white capitalize"
                          >
                            <option value="admin">Admin</option>
                            <option value="analyst">Analyst</option>
                            <option value="read_only">Read-Only</option>
                          </select>
                        </td>
                        <td className="px-4 py-3">
                          <span
                            className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                              u.isActive
                                ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40'
                                : 'bg-red-950 text-red-300 border border-red-800/40'
                            }`}
                          >
                            {u.isActive ? 'Active' : 'Inactive'}
                          </span>
                        </td>
                        <td className="px-4 py-3 text-xs text-ink-muted">
                          {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '-'}
                        </td>
                        <td className="px-4 py-3 text-right space-x-2">
                          <button
                            onClick={() => {
                              setPasswordResetUserId(isResetting ? null : u.id);
                              setResetPasswordValue('');
                            }}
                            className="text-xs px-2.5 py-1 rounded bg-raised border border-hairline text-ink-secondary hover:text-white transition"
                          >
                            {isResetting ? 'Cancel' : 'Change Password'}
                          </button>

                          <button
                            onClick={() => handleToggleActive(u)}
                            className={`text-xs px-2.5 py-1 rounded border transition ${
                              u.isActive
                                ? 'border-yellow-600/40 text-yellow-300 hover:bg-yellow-950/30'
                                : 'border-emerald-600/40 text-emerald-300 hover:bg-emerald-950/30'
                            }`}
                          >
                            {u.isActive ? 'Deactivate' : 'Activate'}
                          </button>

                          <button
                            onClick={() => handleDeleteUser(u)}
                            className="text-xs px-2.5 py-1 rounded border border-red-600/40 text-red-400 hover:bg-red-950/30 transition"
                          >
                            Delete
                          </button>
                        </td>
                      </tr>

                      {/* Inline Password Reset Row */}
                      {isResetting && (
                        <tr className="bg-raised/70 border-b border-hairline">
                          <td colSpan={5} className="px-4 py-3">
                            <div className="flex items-center gap-3">
                              <span className="text-xs font-semibold text-white">
                                New Password for {u.username}:
                              </span>
                              <input
                                type="password"
                                placeholder="Enter at least 8 characters"
                                value={resetPasswordValue}
                                onChange={(e) => setResetPasswordValue(e.target.value)}
                                className="px-3 py-1.5 text-xs bg-panel border border-hairline rounded text-white flex-1 max-w-xs"
                              />
                              <button
                                onClick={() => handleResetPasswordSubmit(u.id)}
                                disabled={updatingPassword}
                                className="px-3 py-1.5 text-xs font-semibold rounded bg-accent text-white hover:brightness-110 transition"
                              >
                                {updatingPassword ? 'Saving...' : 'Set Password'}
                              </button>
                            </div>
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  );
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Footer */}
        <div className="flex justify-end pt-4 border-t border-hairline">
          <button
            onClick={onClose}
            className="px-5 py-2 rounded-lg bg-raised border border-hairline text-ink-secondary hover:text-white transition text-sm"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
