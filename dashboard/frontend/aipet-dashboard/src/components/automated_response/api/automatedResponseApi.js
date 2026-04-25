const BASE = "http://localhost:5001/api/response";
const hdrs = (t) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });

export const fetchThresholds   = (t) => fetch(`${BASE}/thresholds`, { headers: hdrs(t) }).then(r => r.json());
export const updateThreshold   = (t, id, body) => fetch(`${BASE}/thresholds/${id}`, { method: "PUT", headers: hdrs(t), body: JSON.stringify(body) }).then(r => r.json());
export const fetchHistory      = (t, params = {}) => {
  const q = new URLSearchParams({ limit: 50, ...params }).toString();
  return fetch(`${BASE}/history?${q}`, { headers: hdrs(t) }).then(r => r.json());
};
export const fetchHistoryEntry = (t, id) => fetch(`${BASE}/history/${id}`, { headers: hdrs(t) }).then(r => r.json());
export const fetchStats        = (t) => fetch(`${BASE}/stats`, { headers: hdrs(t) }).then(r => r.json());
export const triggerCheck      = (t) => fetch(`${BASE}/check_now`, { method: "POST", headers: hdrs(t) }).then(r => r.json());
