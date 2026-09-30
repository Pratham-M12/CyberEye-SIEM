// frontend/src/api/siem.js

import axios from 'axios';

const client = axios.create({
  baseURL: '/api',
});

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
