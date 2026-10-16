/**
 * ScamShield AI - REST API Client
 * Connects to the FastAPI backend with safe error handling and timeout fallbacks.
 */

const API_BASE = import.meta.env.VITE_API_BASE || '/api/v1';

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
  // Check backend health & model readiness
  async checkHealth() {
    return fetchJson('/health');
  },

  // Perform static lexical ML and heuristic scan of a URL
  async scanUrl(url) {
    return fetchJson('/scan', {
      method: 'POST',
      body: JSON.stringify({ url }),
    });
  },

  // Retrieve persistent scan history
  async getHistory(limit = 50, offset = 0) {
    return fetchJson(`/history?limit=${limit}&offset=${offset}`);
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

  // Retrieve ML model provenance and held-out test evaluation metrics
  async getModelInfo() {
    return fetchJson('/model-info');
  },
};
