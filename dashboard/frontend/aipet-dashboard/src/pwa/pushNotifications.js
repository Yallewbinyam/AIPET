/**
 * AIPET X — PWA Push Notification Helpers (Capability 12)
 */

const API = "http://localhost:5001/api";

export function isPushSupported() {
  return "serviceWorker" in navigator && "PushManager" in window;
}

export function getCurrentPermission() {
  if (!("Notification" in window)) return "unsupported";
  return Notification.permission;
}

export async function requestPermissionAndSubscribe(token) {
  if (!isPushSupported()) {
    return { ok: false, reason: "not_supported" };
  }

  const permission = await Notification.requestPermission();
  if (permission !== "granted") {
    return { ok: false, reason: "permission_denied" };
  }

  const reg = await navigator.serviceWorker.ready;

  let public_key;
  try {
    const keyRes = await fetch(`${API}/push/vapid-public-key`);
    if (!keyRes.ok) throw new Error("vapid key fetch failed");
    ({ public_key } = await keyRes.json());
  } catch {
    return { ok: false, reason: "vapid_key_fetch_failed" };
  }

  let subscription;
  try {
    subscription = await reg.pushManager.subscribe({
      userVisibleOnly: true,
      applicationServerKey: _urlBase64ToUint8Array(public_key),
    });
  } catch (e) {
    return { ok: false, reason: "subscribe_failed", detail: e.message };
  }

  const subData = subscription.toJSON();
  try {
    const subRes = await fetch(`${API}/push/subscribe`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${token}`,
      },
      body: JSON.stringify({
        endpoint:     subData.endpoint,
        keys:         subData.keys,
        user_agent:   navigator.userAgent,
        device_label: _getDeviceLabel(),
      }),
    });
    if (!subRes.ok) {
      return { ok: false, reason: "backend_subscribe_failed" };
    }
  } catch {
    return { ok: false, reason: "backend_subscribe_failed" };
  }

  return { ok: true };
}

export async function sendTestPush(token) {
  const res = await fetch(`${API}/push/test`, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  return res.json();
}

export async function listSubscriptions(token) {
  const res = await fetch(`${API}/push/subscriptions`, {
    headers: { Authorization: `Bearer ${token}` },
  });
  if (!res.ok) return [];
  const data = await res.json();
  return data.subscriptions ?? [];
}

export async function disableSubscription(token, endpoint) {
  const res = await fetch(`${API}/push/unsubscribe`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ endpoint }),
  });
  return res.ok;
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function _urlBase64ToUint8Array(base64String) {
  const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
  const base64  = (base64String + padding).replace(/-/g, "+").replace(/_/g, "/");
  const rawData = window.atob(base64);
  const output  = new Uint8Array(rawData.length);
  for (let i = 0; i < rawData.length; i++) {
    output[i] = rawData.charCodeAt(i);
  }
  return output;
}

function _getDeviceLabel() {
  const ua = navigator.userAgent;
  if (/iPhone/.test(ua))  return "iPhone";
  if (/iPad/.test(ua))    return "iPad";
  if (/Android/.test(ua)) return "Android device";
  return "Desktop browser";
}
