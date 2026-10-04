// frontend/src/api/siem.js

import axios from 'axios';

const client = axios.create({
  baseURL: '/api',
});

let authToken = null;
let onUnauthorizedCallback = null;

export const setAuthToken = (token) => {
  authToken = token;
};

export const setOnUnauthorized = (cb) => {
  onUnauthorizedCallback = cb;
};

client.interceptors.request.use((config) => {
  if (authToken) {
    config.headers.Authorization = `Bearer ${authToken}`;
  }
  return config;
});

client.interceptors.response.use(
  (res) => res,
  (err) => {
    if (err.response && err.response.status === 401 && !err.config?.url?.includes('/auth/login')) {
      if (onUnauthorizedCallback) {
        onUnauthorizedCallback();
      }
    }
    return Promise.reject(err);
  }
);

// --- Auth Endpoints ---
export const loginApi = (username, password) =>
  client.post('/auth/login', { username, password }).then((r) => r.data);

export const getMeApi = () =>
  client.get('/auth/me').then((r) => r.data);

export const logoutApi = () =>
  client.post('/auth/logout').then((r) => r.data);

// --- User Management Endpoints (Admin only) ---
export const getUsers = () =>
  client.get('/users').then((r) => r.data);

export const createUserApi = (userData) =>
  client.post('/users', userData).then((r) => r.data);

export const updateUserApi = (id, updates) =>
  client.patch(`/users/${id}`, updates).then((r) => r.data);

export const deleteUserApi = (id) =>
  client.delete(`/users/${id}`).then((r) => r.data);

// --- Logs & Alerts Endpoints ---
export const getLogs = (params) => client.get('/logs', { params }).then((r) => r.data);

export const getAlerts = (params) => client.get('/alerts', { params }).then((r) => r.data);

export const getAlert = (id) => client.get(`/alerts/${id}`).then((r) => r.data);

export const investigateAlert = (id) =>
  client.post(`/alerts/${id}/investigate`).then((r) => r.data);

export const getAlertSummary = (id) =>
  client.post(`/alerts/${id}/summary`).then((r) => r.data);

export const setAlertStatus = (id, status) =>
  client.patch(`/alerts/${id}/status`, { status }).then((r) => r.data);

export const getTopAttackers = (params) =>
  client.get('/alerts/top-attackers', { params }).then((r) => r.data);

export const getTimeline = (params) =>
  client.get('/stats/timeline', { params }).then((r) => r.data);

export const getSummary = () => client.get('/stats/summary').then((r) => r.data);

export const getUploadConfig = () => client.get('/uploads/config').then((r) => r.data);

export const uploadLogFile = (payload, onUploadProgress) =>
  client
    .post('/uploads', payload, {
      onUploadProgress,
    })
    .then((r) => r.data);

export default client;
