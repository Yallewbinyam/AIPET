const BASE = "http://localhost:5001/api/forecast";
const h = (t) => ({ Authorization: `Bearer ${t}`, "Content-Type": "application/json" });

export const fetchForecasts    = (t, params = {}) => {
  const q = new URLSearchParams({ limit: 50, ...params }).toString();
  return fetch(`${BASE}/scores?${q}`, { headers: h(t) }).then(r => r.json());
};
export const fetchEntityForecast = (t, entity, recompute = false) =>
  fetch(`${BASE}/${encodeURIComponent(entity)}?recompute=${recompute}`, { headers: h(t) }).then(r => r.json());
export const fetchAlerts       = (t, status = "active") =>
  fetch(`${BASE}/alerts?status=${status}`, { headers: h(t) }).then(r => r.json());
export const fetchStats        = (t) =>
  fetch(`${BASE}/stats`, { headers: h(t) }).then(r => r.json());
export const acknowledgeAlert  = (t, id) =>
  fetch(`${BASE}/alerts/${id}/acknowledge`, { method: "PUT", headers: h(t) }).then(r => r.json());
export const dismissAlert      = (t, id) =>
  fetch(`${BASE}/alerts/${id}/dismiss`, { method: "PUT", headers: h(t) }).then(r => r.json());
export const triggerRecompute  = (t) =>
  fetch(`${BASE}/recompute_all`, { method: "POST", headers: h(t) }).then(r => r.json());
