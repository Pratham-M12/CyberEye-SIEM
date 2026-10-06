// frontend/src/components/UserManagementModal.jsx
import React, { useState, useEffect } from 'react';
import { getUsers, createUserApi, updateUserApi, deleteUserApi } from '../api/siem';
import { IconUsers, IconClose } from './ui/Icons.jsx';

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

  // Accessible keyboard handler to close modal on Escape key
  useEffect(() => {
    if (!isOpen) return;
    const handleKeyDown = (e) => {
      if (e.key === 'Escape') {
        onClose();
      }
    };
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [isOpen, onClose]);

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
      className="fixed inset-0 z-50 flex items-center justify-center bg-black/75 backdrop-blur-sm p-3 sm:p-4 md:p-6"
      role="dialog"
      aria-modal="true"
      aria-labelledby="user-mgmt-title"
      onClick={onClose}
    >
      <div
        className="relative w-full max-w-5xl max-h-[92vh] flex flex-col rounded-panel border border-hairline bg-panel shadow-2xl overflow-hidden my-auto"
        onClick={(e) => e.stopPropagation()}
      >
        {/* Modal Header */}
        <div className="shrink-0 flex items-center justify-between border-b border-hairline px-4 sm:px-6 py-3.5 sm:py-4 bg-raised/60">
          <div className="flex items-center gap-3 min-w-0">
            <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-accent text-white shadow-sm">
              <IconUsers className="h-5 w-5 text-white" />
            </div>
            <div className="min-w-0">
              <h2 id="user-mgmt-title" className="text-lg sm:text-xl font-bold text-white truncate">
                User Management &amp; RBAC
              </h2>
              <p className="text-xs text-ink-secondary truncate">
                Admin Console • Manage Operator Accounts &amp; Access Roles
              </p>
            </div>
          </div>
          <button
            type="button"
            onClick={onClose}
            aria-label="Close user management dialog"
            className="rounded-lg p-2 text-ink-secondary hover:bg-raised hover:text-white transition shrink-0 ml-2"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>

        {/* Modal Body - Vertically Scrollable */}
        <div className="flex-1 overflow-y-auto px-4 sm:px-6 py-4 sm:py-6 space-y-5 sm:space-y-6 min-h-0">
          {/* Status Alerts */}
          {error && (
            <div
              role="alert"
              className="rounded-lg border border-red-500/40 bg-red-950/40 p-3 text-sm text-red-300"
            >
              {error}
            </div>
          )}
          {success && (
            <div
              role="status"
              className="rounded-lg border border-emerald-500/40 bg-emerald-950/40 p-3 text-sm text-emerald-300"
            >
              {success}
            </div>
          )}

          {/* Create User Section */}
          <div className="rounded-lg border border-hairline bg-raised/70 p-4 sm:p-5">
            <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-white mb-3 font-mono">
              Provision New User Account
            </h3>
            <form onSubmit={handleCreateUser} className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              <div>
                <label className="block text-xs text-ink-secondary mb-1">Username</label>
                <input
                  type="text"
                  placeholder="operator_name"
                  value={newUsername}
                  onChange={(e) => setNewUsername(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white focus:border-accent focus:outline-none"
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
                  className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white focus:border-accent focus:outline-none"
                  required
                />
              </div>
              <div>
                <label className="block text-xs text-ink-secondary mb-1">Role</label>
                <select
                  value={newRole}
                  onChange={(e) => setNewRole(e.target.value)}
                  className="w-full px-3 py-2 text-sm bg-panel border border-hairline rounded text-white focus:border-accent focus:outline-none"
                >
                  <option value="analyst">Analyst</option>
                  <option value="read_only">Read-Only</option>
                  <option value="admin">Administrator</option>
                </select>
              </div>
              <div className="flex items-end sm:col-span-2 lg:col-span-1">
                <button
                  type="submit"
                  disabled={creating}
                  className="w-full py-2 px-4 rounded bg-accent hover:brightness-110 text-white font-medium text-sm transition disabled:opacity-50 min-h-[38px] flex items-center justify-center shadow-sm"
                >
                  {creating ? 'Creating...' : '+ Add User'}
                </button>
              </div>
            </form>
          </div>

          {/* Existing Users Section */}
          <div className="space-y-3">
            <div className="flex items-center justify-between">
              <h3 className="text-xs sm:text-sm font-semibold uppercase tracking-wider text-white font-mono">
                System Operators ({users.length})
              </h3>
              {loading && <span className="text-xs text-ink-muted">Refreshing list...</span>}
            </div>

            {/* Desktop & Tablet Table View (md and up) */}
            <div className="hidden md:block rounded-lg border border-hairline bg-raised/20 overflow-hidden">
              <table className="w-full text-left text-sm text-ink-secondary border-collapse table-auto">
                <thead className="bg-raised text-xs uppercase tracking-wider text-ink-muted border-b border-hairline">
                  <tr>
                    <th scope="col" className="px-4 py-3 font-semibold">Username</th>
                    <th scope="col" className="px-3 py-3 font-semibold w-32">Role</th>
                    <th scope="col" className="px-3 py-3 font-semibold w-24">Status</th>
                    <th scope="col" className="px-3 py-3 font-semibold w-28">Created</th>
                    <th scope="col" className="px-4 py-3 font-semibold text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-hairline">
                  {users.map((u) => {
                    const isCurrent = u.username === currentUsername;
                    const isResetting = passwordResetUserId === u.id;

                    return (
                      <React.Fragment key={u.id}>
                        <tr className="hover:bg-raised/40 transition">
                          <td className="px-4 py-3 font-medium text-white">
                            <div className="flex items-center gap-2 min-w-0">
                              <span
                                className="truncate font-mono text-sm text-white max-w-[160px] lg:max-w-[220px]"
                                title={u.username}
                              >
                                {u.username}
                              </span>
                              {isCurrent && (
                                <span className="shrink-0 text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
                                  You
                                </span>
                              )}
                            </div>
                          </td>
                          <td className="px-3 py-3">
                            <select
                              value={u.role}
                              onChange={(e) => handleRoleChange(u.id, e.target.value)}
                              aria-label={`Change role for ${u.username}`}
                              className="text-xs px-2.5 py-1.5 bg-panel border border-hairline rounded text-white capitalize focus:border-accent focus:outline-none"
                            >
                              <option value="admin">Admin</option>
                              <option value="analyst">Analyst</option>
                              <option value="read_only">Read-Only</option>
                            </select>
                          </td>
                          <td className="px-3 py-3">
                            <span
                              className={`inline-flex items-center text-xs px-2.5 py-0.5 rounded-full font-medium ${
                                u.isActive
                                  ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40'
                                  : 'bg-red-950 text-red-300 border border-red-800/40'
                              }`}
                            >
                              {u.isActive ? 'Active' : 'Inactive'}
                            </span>
                          </td>
                          <td className="px-3 py-3 text-xs text-ink-muted tabular font-mono">
                            {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—'}
                          </td>
                          <td className="px-4 py-3 text-right">
                            <div className="flex flex-wrap items-center justify-end gap-1.5">
                              <button
                                type="button"
                                onClick={() => {
                                  setPasswordResetUserId(isResetting ? null : u.id);
                                  setResetPasswordValue('');
                                }}
                                aria-label={`${isResetting ? 'Cancel password change' : 'Change password'} for ${u.username}`}
                                className={`text-xs px-2.5 py-1.5 min-h-[30px] rounded border transition font-medium whitespace-nowrap ${
                                  isResetting
                                    ? 'bg-accent/20 border-accent text-accent'
                                    : 'bg-raised border-hairline text-ink-secondary hover:text-white hover:border-hairline/80'
                                }`}
                              >
                                {isResetting ? 'Cancel' : 'Change Password'}
                              </button>

                              <button
                                type="button"
                                onClick={() => handleToggleActive(u)}
                                aria-label={`${u.isActive ? 'Deactivate' : 'Activate'} user account ${u.username}`}
                                className={`text-xs px-2.5 py-1.5 min-h-[30px] rounded border transition font-medium whitespace-nowrap ${
                                  u.isActive
                                    ? 'border-yellow-600/40 text-yellow-300 hover:bg-yellow-950/30'
                                    : 'border-emerald-600/40 text-emerald-300 hover:bg-emerald-950/30'
                                }`}
                              >
                                {u.isActive ? 'Deactivate' : 'Activate'}
                              </button>

                              <button
                                type="button"
                                onClick={() => handleDeleteUser(u)}
                                aria-label={`Delete user account ${u.username}`}
                                className="text-xs px-2.5 py-1.5 min-h-[30px] rounded border border-red-600/40 text-red-400 hover:bg-red-950/30 transition font-medium whitespace-nowrap"
                              >
                                Delete
                              </button>
                            </div>
                          </td>
                        </tr>

                        {/* Inline Desktop Password Reset Row */}
                        {isResetting && (
                          <tr className="bg-raised/80 border-b border-hairline">
                            <td colSpan={5} className="px-4 py-3">
                              <div className="flex flex-wrap items-center gap-2 sm:gap-3">
                                <span className="text-xs font-semibold text-white whitespace-nowrap">
                                  New Password for <span className="text-accent font-mono">{u.username}</span>:
                                </span>
                                <input
                                  type="password"
                                  placeholder="Enter at least 8 characters"
                                  value={resetPasswordValue}
                                  onChange={(e) => setResetPasswordValue(e.target.value)}
                                  aria-label={`New password for ${u.username}`}
                                  className="px-3 py-1.5 text-xs bg-panel border border-hairline rounded text-white flex-1 min-w-[180px] max-w-sm focus:border-accent focus:outline-none"
                                />
                                <button
                                  type="button"
                                  onClick={() => handleResetPasswordSubmit(u.id)}
                                  disabled={updatingPassword}
                                  className="px-3.5 py-1.5 text-xs font-semibold rounded bg-accent text-white hover:brightness-110 transition disabled:opacity-50 whitespace-nowrap"
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

            {/* Mobile Card-Based User Rows (< md, 768px down) */}
            <div className="space-y-3 md:hidden">
              {users.map((u) => {
                const isCurrent = u.username === currentUsername;
                const isResetting = passwordResetUserId === u.id;

                return (
                  <div
                    key={u.id}
                    className="rounded-lg border border-hairline bg-raised/50 p-3.5 space-y-3 shadow-sm"
                  >
                    {/* Header: Username, Current badge, Status */}
                    <div className="flex items-center justify-between gap-2">
                      <div className="flex items-center gap-2 min-w-0">
                        <span
                          className="font-mono text-sm font-semibold text-white truncate max-w-[200px]"
                          title={u.username}
                        >
                          {u.username}
                        </span>
                        {isCurrent && (
                          <span className="shrink-0 text-[10px] font-mono uppercase tracking-wider px-1.5 py-0.5 rounded bg-blue-900/60 text-blue-300 border border-blue-700/50">
                            You
                          </span>
                        )}
                      </div>
                      <span
                        className={`shrink-0 text-xs px-2.5 py-0.5 rounded-full font-medium ${
                          u.isActive
                            ? 'bg-emerald-950 text-emerald-300 border border-emerald-800/40'
                            : 'bg-red-950 text-red-300 border border-red-800/40'
                        }`}
                      >
                        {u.isActive ? 'Active' : 'Inactive'}
                      </span>
                    </div>

                    {/* Role & Created Date Row */}
                    <div className="flex flex-wrap items-center justify-between gap-2 pt-2 border-t border-hairline/40 text-xs">
                      <div className="flex items-center gap-2">
                        <span className="text-ink-muted">Role:</span>
                        <select
                          value={u.role}
                          onChange={(e) => handleRoleChange(u.id, e.target.value)}
                          aria-label={`Change role for ${u.username}`}
                          className="text-xs px-2.5 py-1 bg-panel border border-hairline rounded text-white capitalize focus:border-accent focus:outline-none"
                        >
                          <option value="admin">Admin</option>
                          <option value="analyst">Analyst</option>
                          <option value="read_only">Read-Only</option>
                        </select>
                      </div>
                      <div className="text-ink-muted tabular font-mono text-[11px]">
                        Created: {u.createdAt ? new Date(u.createdAt).toLocaleDateString() : '—'}
                      </div>
                    </div>

                    {/* Actions Toolbar */}
                    <div className="flex flex-wrap items-center gap-2 pt-2 border-t border-hairline/40">
                      <button
                        type="button"
                        onClick={() => {
                          setPasswordResetUserId(isResetting ? null : u.id);
                          setResetPasswordValue('');
                        }}
                        aria-label={`${isResetting ? 'Cancel password change' : 'Change password'} for ${u.username}`}
                        className={`flex-1 min-h-[36px] text-xs px-2.5 py-1.5 rounded border transition font-medium text-center ${
                          isResetting
                            ? 'bg-accent/20 border-accent text-accent'
                            : 'bg-panel border-hairline text-ink-secondary hover:text-white'
                        }`}
                      >
                        {isResetting ? 'Cancel' : 'Change Password'}
                      </button>

                      <button
                        type="button"
                        onClick={() => handleToggleActive(u)}
                        aria-label={`${u.isActive ? 'Deactivate' : 'Activate'} user account ${u.username}`}
                        className={`flex-1 min-h-[36px] text-xs px-2.5 py-1.5 rounded border transition font-medium text-center ${
                          u.isActive
                            ? 'border-yellow-600/40 text-yellow-300 hover:bg-yellow-950/30'
                            : 'border-emerald-600/40 text-emerald-300 hover:bg-emerald-950/30'
                        }`}
                      >
                        {u.isActive ? 'Deactivate' : 'Activate'}
                      </button>

                      <button
                        type="button"
                        onClick={() => handleDeleteUser(u)}
                        aria-label={`Delete user account ${u.username}`}
                        className="min-h-[36px] text-xs px-3 py-1.5 rounded border border-red-600/40 text-red-400 hover:bg-red-950/30 transition font-medium"
                      >
                        Delete
                      </button>
                    </div>

                    {/* Inline Mobile Password Reset */}
                    {isResetting && (
                      <div className="p-3 rounded bg-panel border border-accent/40 space-y-2 animate-fade">
                        <label className="block text-xs font-semibold text-white">
                          New Password for <span className="text-accent font-mono">{u.username}</span> (min 8 chars):
                        </label>
                        <input
                          type="password"
                          placeholder="Enter at least 8 characters"
                          value={resetPasswordValue}
                          onChange={(e) => setResetPasswordValue(e.target.value)}
                          aria-label={`New password for ${u.username}`}
                          className="w-full px-3 py-2 text-xs bg-raised border border-hairline rounded text-white focus:border-accent focus:outline-none"
                        />
                        <button
                          type="button"
                          onClick={() => handleResetPasswordSubmit(u.id)}
                          disabled={updatingPassword}
                          className="w-full py-2 text-xs font-semibold rounded bg-accent text-white hover:brightness-110 transition disabled:opacity-50 min-h-[36px]"
                        >
                          {updatingPassword ? 'Saving...' : 'Set Password'}
                        </button>
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </div>
        </div>

        {/* Modal Footer */}
        <div className="shrink-0 flex justify-end px-4 sm:px-6 py-3.5 sm:py-4 border-t border-hairline bg-raised/40">
          <button
            type="button"
            onClick={onClose}
            aria-label="Close user management dialog"
            className="px-5 py-2 rounded-lg bg-raised border border-hairline text-ink-secondary hover:text-white hover:border-accent transition text-sm font-medium"
          >
            Close
          </button>
        </div>
      </div>
    </div>
  );
}
