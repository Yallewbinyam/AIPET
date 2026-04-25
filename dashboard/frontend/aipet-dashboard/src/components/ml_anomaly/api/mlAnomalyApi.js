/**
 * ml_anomaly API client — all calls to /api/ml/anomaly/*
 * Each function accepts `token` as first arg and returns a Promise.
 * Errors are re-thrown as Error objects with HTTP status embedded.
 */
import axios from "axios";

const BASE = "http://localhost:5001/api/ml/anomaly";
const TIMEOUT = 30000;

function headers(token) {
  return { Authorization: `Bearer ${token}` };
}

async function call(method, url, token, data) {
  try {
    const res = await axios({ method, url, headers: headers(token), data, timeout: TIMEOUT });
    return res.data;
  } catch (err) {
    const status = err.response?.status ?? 0;
    const msg    = err.response?.data?.error ?? err.message ?? "Request failed";
    throw Object.assign(new Error(`[${status}] ${msg}`), { status });
  }
}

export const getFeatures            = (token)            => call("get",  `${BASE}/features`,           token);
export const trainModel             = (token, body = {}) => call("post", `${BASE}/train`,               token, body);
export const predictHost            = (token, body)      => call("post", `${BASE}/predict`,             token, body);
export const predictReal            = (token, body)      => call("post", `${BASE}/predict_real`,        token, body);
export const extractFeatures        = (token, body)      => call("post", `${BASE}/extract`,             token, body);
export const retrainNow             = (token)            => call("post", `${BASE}/retrain_now`,         token);
export const getRetrainStatus       = (token, taskId)    => call("get",  `${BASE}/retrain_status/${taskId}`, token);
export const listModels             = (token)            => call("get",  `${BASE}/models`,              token);
export const listDetections         = (token, limit=50)  => call("get",  `${BASE}/detections?limit=${limit}`, token);
export const getDetectionExplain    = (token, id)        => call("get",  `${BASE}/detections/${id}/explain`, token);
