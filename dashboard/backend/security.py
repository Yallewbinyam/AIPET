# =============================================================
# AIPET Cloud — Security Headers, Rate Limiting, Talisman
# =============================================================

from flask import request, jsonify


# ── CSP policy ────────────────────────────────────────────
CSP = {
    "default-src": ["'self'"],
    "script-src":  ["'self'", "'unsafe-inline'", "'unsafe-eval'",
                    "https://js.stripe.com", "https://fonts.googleapis.com"],
    "style-src":   ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
    "img-src":     ["'self'", "data:", "https:"],
    "font-src":    ["'self'", "data:", "https://fonts.gstatic.com"],
    "connect-src": ["'self'", "http://localhost:5001", "https://localhost:5001",
                    "https://api.stripe.com", "https://aipet.io",
                    "https://services.nvd.nist.gov"],
    "frame-src":   ["https://js.stripe.com", "https://hooks.stripe.com"],
    "object-src":  ["'none'"],
    "base-uri":    ["'self'"],
    "form-action": ["'self'"],
}


def init_security(app):
    """
    Apply security hardening:
      1. Flask-Talisman for HSTS + CSP
      2. Explicit after_request headers for non-Talisman extras
      3. Error handlers for 429 (rate limit) and 422 (validation)
    """
    try:
        from flask_talisman import Talisman
        # force_https=False — HTTPS redirect handled by force_https() in app_cloud.py
        Talisman(
            app,
            force_https=False,
            strict_transport_security=True,
            strict_transport_security_max_age=31536000,
            strict_transport_security_include_subdomains=True,
            strict_transport_security_preload=True,
            frame_options="DENY",
            frame_options_allow_from=None,
            content_security_policy=CSP,
            content_security_policy_nonce_in=["script-src"],
            referrer_policy="strict-origin-when-cross-origin",
            permissions_policy={
                "camera": "()",
                "microphone": "()",
                "geolocation": "()",
                "payment": "()",
                "usb": "()",
            },
        )
    except Exception:
        _add_manual_headers(app)
        return

    @app.after_request
    def extra_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Server"]                  = "AIPET"
        response.headers.pop("X-Powered-By", None)
        return response

    _add_error_handlers(app)


def _add_manual_headers(app):
    @app.after_request
    def add_security_headers(response):
        response.headers["X-Frame-Options"]        = "DENY"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-XSS-Protection"]       = "1; mode=block"
        response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
        response.headers["Permissions-Policy"]     = (
            "camera=(), microphone=(), geolocation=(), payment=(), usb=()"
        )
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' http://localhost:5001 https://api.stripe.com https://aipet.io; "
            "frame-src https://js.stripe.com; "
            "object-src 'none';"
        )
        if request.is_secure:
            response.headers["Strict-Transport-Security"] = (
                "max-age=31536000; includeSubDomains; preload"
            )
        response.headers["Server"] = "AIPET"
        response.headers.pop("X-Powered-By", None)
        return response

    _add_error_handlers(app)


def _add_error_handlers(app):
    @app.errorhandler(429)
    def rate_limit_exceeded(e):
        return jsonify({
            "error":       "Rate limit exceeded",
            "message":     str(e.description),
            "retry_after": getattr(e, "retry_after", 60),
        }), 429

    @app.errorhandler(422)
    def validation_error(e):
        return jsonify({
            "error":   "Validation failed",
            "message": str(e),
        }), 422
