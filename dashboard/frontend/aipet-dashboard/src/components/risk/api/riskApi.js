const BASE = "http://localhost:5001/api/risk";

const hdrs = (token) => ({
  Authorization: `Bearer ${token}`,
  "Content-Type": "application/json",
});

export const fetchScores = (token, { limit = 50, minScore = 0, order = "desc", offset = 0 } = {}) =>
  fetch(`${BASE}/scores?limit=${limit}&min_score=${minScore}&order=${order}&offset=${offset}`, { headers: hdrs(token) })
    .then((r) => r.json());

export const fetchTop = (token, limit = 10) =>
  fetch(`${BASE}/top?limit=${limit}`, { headers: hdrs(token) }).then((r) => r.json());

export const fetchStats = (token) =>
  fetch(`${BASE}/stats`, { headers: hdrs(token) }).then((r) => r.json());

export const fetchEntity = (token, entity, recompute = false) =>
  fetch(`${BASE}/${encodeURIComponent(entity)}?recompute=${recompute}`, { headers: hdrs(token) })
    .then((r) => r.json());

export const triggerRecompute = (token) =>
  fetch(`${BASE}/recompute_now`, { method: "POST", headers: hdrs(token) })
    .then((r) => r.json());
