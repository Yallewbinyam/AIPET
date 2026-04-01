# =============================================================
# AIPET Cloud — Security Headers and Helpers
# Adds HTTP security headers to every response.
# Import and call init_security(app) in create_app().
# =============================================================

from flask import request


def init_security(app):
    """
    Register security headers on every HTTP response.
    Call this inside create_app() after creating the Flask app.

    These headers protect users from:
    - Clickjacking (X-Frame-Options)
    - XSS attacks (Content-Security-Policy)
    - MIME sniffing (X-Content-Type-Options)
    - Protocol downgrade attacks (Strict-Transport-Security)
    - Information leakage (Referrer-Policy, Server header)
    """

    @app.after_request
    def add_security_headers(response):
        # ── Prevent clickjacking ───────────────────────────────
        # Stops attackers from embedding your site in an iframe
        # and tricking users into clicking hidden buttons.
        response.headers['X-Frame-Options'] = 'DENY'

        # ── Prevent MIME sniffing ──────────────────────────────
        # Stops the browser from guessing the content type.
        # Without this, an attacker could upload a file that
        # the browser runs as JavaScript.
        response.headers['X-Content-Type-Options'] = 'nosniff'

        # ── XSS Protection ────────────────────────────────────
        # Enables the browser's built-in XSS filter.
        # Legacy header — still supported by older browsers.
        response.headers['X-XSS-Protection'] = '1; mode=block'

        # ── Referrer Policy ───────────────────────────────────
        # Controls how much referrer information is sent.
        # 'strict-origin-when-cross-origin' means:
        # - Full URL sent for same-origin requests
        # - Only origin sent for cross-origin HTTPS requests
        # - Nothing sent for cross-origin HTTP requests
        response.headers['Referrer-Policy'] = \
            'strict-origin-when-cross-origin'

        # ── Permissions Policy ─────────────────────────────────
        # Disables browser features that AIPET doesn't need.
        # Prevents malicious scripts from accessing camera,
        # microphone, geolocation, etc.
        response.headers['Permissions-Policy'] = (
            'camera=(), microphone=(), geolocation=(), '
            'payment=(), usb=(), magnetometer=(), gyroscope=()'
        )

        # ── Content Security Policy ────────────────────────────
        # The most powerful security header.
        # Controls exactly which resources the browser can load.
        # This prevents XSS attacks by blocking inline scripts
        # and scripts from untrusted sources.
        response.headers['Content-Security-Policy'] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' "
            "https://js.stripe.com; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: https:; "
            "font-src 'self' data:; "
            "connect-src 'self' https://api.stripe.com "
            "http://localhost:5001 https://aipet.io; "
            "frame-src https://js.stripe.com "
            "https://hooks.stripe.com; "
            "object-src 'none';"
        )

        # ── HSTS (HTTPS only) ──────────────────────────────────
        # Tells browsers to ALWAYS use HTTPS for this domain.
        # max-age=31536000 = 1 year.
        # includeSubDomains protects all subdomains too.
        # Only active in production (requires real HTTPS).
        if request.is_secure:
            response.headers['Strict-Transport-Security'] = (
                'max-age=31536000; includeSubDomains; preload'
            )

        # ── Remove server information ──────────────────────────
        # By default Flask sends 'Server: Werkzeug/x.x.x'
        # which tells attackers exactly what software you run.
        # We remove it to make reconnaissance harder.
        response.headers.pop('Server', None)
        response.headers['Server'] = 'AIPET'

        return response