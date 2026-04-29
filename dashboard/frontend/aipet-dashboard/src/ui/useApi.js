import { useCallback, useEffect, useRef, useState } from "react";
import axios from "axios";

// Hook for axios calls with the AIPET X JWT bearer attached.
//
// Decisions documented (Phase C):
//   - JWT is read from localStorage('aipet_token') -- the same key
//     existing components use (App.js:29468).
//   - There is no global toast context in this phase; the existing
//     `showToast` prop pattern is the canonical channel. Callers
//     pass `onError` if they want to surface an error to the user.
//   - Auto-fetch on mount when `url` is provided (GET, no body);
//     for non-GET or on-demand calls, pass `manual: true` and use
//     `request({ method, url, data, params })` from the return.
//
// Return shape:
//   { data, loading, error, refetch, request }
//   - error: { status, message, body }  (or null)
//   - refetch(): re-runs the auto-fetch with the same args
//   - request(opts): one-off call; returns the response data,
//     throws the same error shape on failure.

const API_BASE = "/api";

function _getToken() {
  if (typeof localStorage === "undefined") return null;
  return localStorage.getItem("aipet_token");
}

function _normalizeError(err) {
  if (err && err.response) {
    const body = err.response.data || {};
    // Coerce the surfaced message to a guaranteed non-empty string.
    // A backend that returns {"error": {...}} (non-string) would
    // otherwise propagate an object into the Toast renderer, where
    // {toast.message} is a React child slot -- that triggers the
    // dev-mode runtime overlay reading "[object Object]".
    const status  = err.response.status;
    const raw     = body.message || body.error;
    const message = (typeof raw === "string" && raw.length > 0)
      ? raw
      : `Request failed (${status})`;
    return {
      status,
      message,
      body,
    };
  }
  // No response means the request never reached the server (DNS,
  // server down, offline, CORS pre-flight fail). Spec'd retry copy.
  return {
    status:  0,
    message: "Network error — please retry.",
    body:    null,
  };
}

export default function useApi(initialUrl, options = {}) {
  const {
    method = "GET",
    params,
    data: initialData,
    manual = false,
    onError,
    onSuccess,
  } = options;

  const [data, setData]       = useState(null);
  const [loading, setLoading] = useState(!manual && !!initialUrl);
  const [error, setError]     = useState(null);

  // Latch the latest options in a ref so refetch() never closes
  // over stale values when the component re-renders.
  const optsRef = useRef({ url: initialUrl, method, params, data: initialData });
  useEffect(() => {
    optsRef.current = { url: initialUrl, method, params, data: initialData };
  }, [initialUrl, method, params, initialData]);

  const cbRef = useRef({ onError, onSuccess });
  useEffect(() => { cbRef.current = { onError, onSuccess }; }, [onError, onSuccess]);

  const _runOnce = useCallback(async (overrideOpts) => {
    const merged = { ...optsRef.current, ...(overrideOpts || {}) };
    if (!merged.url) {
      throw new Error("useApi: no url provided");
    }
    const token = _getToken();
    setLoading(true);
    setError(null);
    try {
      const res = await axios.request({
        url:     merged.url.startsWith("http") ? merged.url : `${API_BASE}${merged.url}`,
        method:  merged.method || "GET",
        params:  merged.params,
        data:    merged.data,
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      });
      setData(res.data);
      if (cbRef.current.onSuccess) cbRef.current.onSuccess(res.data);
      return res.data;
    } catch (rawErr) {
      const e = _normalizeError(rawErr);
      setError(e);
      if (cbRef.current.onError) cbRef.current.onError(e);
      throw e;
    } finally {
      setLoading(false);
    }
  }, []);

  // Auto-fetch on mount + whenever initialUrl/params change.
  useEffect(() => {
    if (manual || !initialUrl) return;
    _runOnce().catch(() => {/* error already captured into state */});
  }, [initialUrl, manual, _runOnce]);

  return {
    data,
    loading,
    error,
    refetch: () => _runOnce(),
    request: (opts) => _runOnce(opts),
  };
}
