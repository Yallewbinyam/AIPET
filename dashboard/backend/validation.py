# ============================================================
# AIPET X — Input Validation Helpers
# ============================================================

import re
import ipaddress
from functools import wraps
from flask import request, jsonify


# ── Field validators ──────────────────────────────────────

def is_email(v: str) -> bool:
    return bool(re.match(r'^[^@\s]+@[^@\s]+\.[^@\s]+$', v.strip()))


def is_safe_string(v: str, max_len: int = 256) -> bool:
    """No null bytes, control chars, or excessively long strings."""
    if not isinstance(v, str) or len(v) > max_len:
        return False
    return '\x00' not in v


def is_ip_or_cidr(v: str) -> bool:
    v = v.strip()
    try:
        ipaddress.ip_address(v)
        return True
    except ValueError:
        pass
    try:
        ipaddress.ip_network(v, strict=False)
        return True
    except ValueError:
        pass
    # Allow hostnames: letters, digits, hyphens, dots
    return bool(re.match(r'^[a-zA-Z0-9._\-]{1,253}$', v))


def is_ip(v: str) -> bool:
    """Accepts only a valid IPv4 or IPv6 address — no CIDRs, no hostnames."""
    try:
        ipaddress.ip_address(str(v).strip())
        return True
    except ValueError:
        return False


def is_positive_int(v, max_val: int = 100_000) -> bool:
    try:
        n = int(v)
        return 1 <= n <= max_val
    except (TypeError, ValueError):
        return False


def is_float_range(min_val: float, max_val: float):
    """Returns a validator: float strictly within (min_val, max_val)."""
    def validator(v) -> bool:
        try:
            return min_val < float(v) < max_val
        except (TypeError, ValueError):
            return False
    return validator


def is_int_range(min_val: int, max_val: int):
    """Returns a validator: int within [min_val, max_val] inclusive."""
    def validator(v) -> bool:
        try:
            n = int(v)
            return min_val <= n <= max_val
        except (TypeError, ValueError):
            return False
    return validator


def is_dict(v) -> bool:
    return isinstance(v, dict)


def strip_html(v: str) -> str:
    """Remove any HTML/script tags from a string."""
    return re.sub(r'<[^>]+>', '', v)


# ── Schema-based validator ────────────────────────────────

def validate_body(schema: dict):
    """
    Decorator factory. schema maps field names to validator callables
    that return True/False. Required fields have truthy values;
    optional fields are wrapped in Optional().

    Example:
        @validate_body({
            "email":    is_email,
            "password": lambda v: is_safe_string(v, 128),
        })
        def my_route(): ...
    """
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            data = request.get_json(silent=True) or {}
            errors = {}
            for field, validator in schema.items():
                if isinstance(validator, _Optional):
                    if field in data and data[field] is not None:
                        if not validator.fn(data[field]):
                            errors[field] = f"Invalid value for '{field}'"
                else:
                    if field not in data or data[field] is None or data[field] == "":
                        errors[field] = f"'{field}' is required"
                    elif not validator(data[field]):
                        errors[field] = f"Invalid value for '{field}'"
            if errors:
                return jsonify({"error": "Validation failed", "fields": errors}), 422
            return f(*args, **kwargs)
        return wrapper
    return decorator


class _Optional:
    def __init__(self, fn):
        self.fn = fn

def optional(fn):
    return _Optional(fn)


# ── Common schemas ────────────────────────────────────────

LOGIN_SCHEMA = {
    "email":    is_email,
    "password": lambda v: is_safe_string(v, 128) and len(str(v)) >= 1,
}

REGISTER_SCHEMA = {
    "email":    is_email,
    "password": lambda v: is_safe_string(v, 128) and len(str(v)) >= 8,
    "name":     lambda v: is_safe_string(v, 128) and len(str(v).strip()) >= 1,
}

SCAN_TARGET_SCHEMA = {
    "target": is_ip_or_cidr,
}

CALENDAR_EVENT_SCHEMA = {
    "title":      lambda v: is_safe_string(v, 256) and len(str(v).strip()) >= 1,
    "start_date": lambda v: is_safe_string(v, 64),
    "event_type": optional(lambda v: v in ("scan","compliance","incident","general")),
    "priority":   optional(lambda v: v in ("low","medium","high","critical")),
}

ISSUE_SCHEMA = {
    "title":    lambda v: is_safe_string(v, 256) and len(str(v).strip()) >= 1,
    "priority": optional(lambda v: v in ("low","medium","high","critical")),
    "status":   optional(lambda v: v in ("open","in-progress","resolved","closed")),
}

CHANGE_PASSWORD_SCHEMA = {
    "current_password": lambda v: is_safe_string(v, 128) and len(str(v)) >= 1,
    "new_password":     lambda v: is_safe_string(v, 128) and len(str(v)) >= 8,
}

TELEMETRY_SCHEMA = {
    "agent_id":    lambda v: is_safe_string(v, 128) and bool(re.match(r'^[\w\-]+$', str(v))),
    "cpu_percent": lambda v: isinstance(v, (int, float)) and 0 <= v <= 100,
    "mem_percent": lambda v: isinstance(v, (int, float)) and 0 <= v <= 100,
}

ML_ANOMALY_TRAIN_SCHEMA = {
    "contamination":  optional(is_float_range(0.0, 0.5)),
    "n_estimators":   optional(is_int_range(50, 1000)),
    "training_mode":  optional(lambda v: v in ("synthetic", "real_scans")),
}

ML_ANOMALY_PREDICT_SCHEMA = {
    "sample":        is_dict,
    "target_ip":     optional(lambda v: is_safe_string(v, 64) and is_ip_or_cidr(v)),
    "target_device": optional(lambda v: is_safe_string(v, 255)),
}

ML_ANOMALY_EXTRACT_SCHEMA = {
    "host_ip": is_ip,
}

ML_ANOMALY_PREDICT_REAL_SCHEMA = {
    "host_ip":       is_ip,
    "target_device": optional(lambda v: is_safe_string(v, 255)),
}

BUILD_DEVICE_BASELINE_SCHEMA = {
    "host_ip": is_ip,
}
