/**
 * ScamShield AI - Multi-Modal API Client
 * Provides safe HTTP communication for Message, URL, Screenshot, and Email threat analysis.
 */

const rawBase = import.meta.env.VITE_API_BASE || import.meta.env.VITE_API_BASE_URL || '';
const API_BASE = rawBase 
  ? (rawBase.endsWith('/api/v1') ? rawBase : `${rawBase.replace(/\/+$/, '')}/api/v1`)
  : '/api/v1';

async function fetchJson(endpoint, options = {}) {
  const url = `${API_BASE}${endpoint}`;
  const response = await fetch(url, {
    headers: {
      'Content-Type': 'application/json',
      ...(options.headers || {}),
    },
    ...options,
  });

  if (!response.ok) {
    let errorDetail = 'API request failed';
    try {
      const errData = await response.json();
      errorDetail = errData.detail || errData.message || errorDetail;
    } catch {
      errorDetail = `Server returned status ${response.status} (${response.statusText})`;
    }
    const error = new Error(errorDetail);
    error.status = response.status;
    throw error;
  }

  return response.json();
}

export const api = {
  // Check backend health & readiness
  async checkHealth() {
    return fetchJson('/health');
  },

  // 1. Static URL Scan
  async scanUrl(url) {
    return fetchJson('/scan/url', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },

  // 2. Message / SMS / Chat Scan
  async scanMessage(text) {
    return fetchJson('/scan/message', {
      method: 'POST',
      body: JSON.stringify({ text }),
    });
  },

  // 3. Screenshot OCR Scan
  async scanScreenshot(file) {
    const formData = new FormData();
    formData.append('file', file);

    const url = `${API_BASE}/scan/screenshot`;
    const response = await fetch(url, {
      method: 'POST',
      body: formData,
    });

    if (!response.ok) {
      let errorDetail = 'Screenshot scan failed';
      try {
        const errData = await response.json();
        errorDetail = errData.detail || errData.message || errorDetail;
      } catch {
        errorDetail = `Server returned status ${response.status} (${response.statusText})`;
      }
      const error = new Error(errorDetail);
      error.status = response.status;
      throw error;
    }

    return response.json();
  },

  // 4. Email Phishing Scan
  async scanEmail({ body, subject, sender }) {
    return fetchJson('/scan/email', {
      method: 'POST',
      body: JSON.stringify({ body, subject, sender }),
    });
  },

  // Retrieve persistent scan history with modality filtering
  async getHistory(scanType = 'all', limit = 50, offset = 0) {
    const typeParam = scanType && scanType !== 'all' ? `&scan_type=${encodeURIComponent(scanType)}` : '';
    return fetchJson(`/history?limit=${limit}&offset=${offset}${typeParam}`);
  },

  // Delete a history record
  async deleteHistoryItem(id) {
    return fetchJson(`/history/${id}`, {
      method: 'DELETE',
    });
  },

  // Clear all scan history
  async clearHistory() {
    return fetchJson('/history', {
      method: 'DELETE',
    });
  },

  // Retrieve aggregate threat analytics
  async getAnalytics() {
    return fetchJson('/analytics');
  },

  // Retrieve ML model provenance and evaluation metrics
  async getModelInfo() {
    return fetchJson('/model-info');
  },
};
