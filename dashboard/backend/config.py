# =============================================================
# AIPET Cloud — Configuration
# =============================================================
import os
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY                    = os.environ.get("SECRET_KEY", "aipet-change-in-production")
    JWT_SECRET_KEY                = os.environ.get("JWT_SECRET_KEY")
    JWT_ACCESS_TOKEN_EXPIRES      = 900    # 15 minutes
    JWT_REFRESH_TOKEN_EXPIRES     = 86400  # 24 hours
    # Cookie security flags
    SESSION_COOKIE_SECURE   = True   # Only send cookies over HTTPS
    SESSION_COOKIE_HTTPONLY = True   # Block JavaScript access to cookies
    SESSION_COOKIE_SAMESITE = 'Lax' # Prevent CSRF attacks
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    # Flask-Limiter shared counter store — Redis db 1 (db 0 = Celery broker/results)
    # Override with FLASK_LIMITER_STORAGE_URI env var for production.
    # Falls back to in-memory per-worker if Redis is unreachable (in_memory_fallback_enabled=True).
    FLASK_LIMITER_STORAGE_URI     = os.environ.get("FLASK_LIMITER_STORAGE_URI", "redis://localhost:6379/1")
    RATELIMIT_STORAGE_URI         = FLASK_LIMITER_STORAGE_URI

    # Stripe
    STRIPE_SECRET_KEY             = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY        = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    STRIPE_WEBHOOK_SECRET         = os.environ.get('STRIPE_WEBHOOK_SECRET')
    STRIPE_PRICE_PROFESSIONAL     = os.environ.get('STRIPE_PRICE_PROFESSIONAL')
    STRIPE_PRICE_ENTERPRISE       = os.environ.get('STRIPE_PRICE_ENTERPRISE')
    STRIPE_PRICE_PROFESSIONAL_USD = os.environ.get('STRIPE_PRICE_PROFESSIONAL_USD')
    STRIPE_PRICE_PROFESSIONAL_EUR = os.environ.get('STRIPE_PRICE_PROFESSIONAL_EUR')
    STRIPE_PRICE_PROFESSIONAL_JPY = os.environ.get('STRIPE_PRICE_PROFESSIONAL_JPY')
    STRIPE_PRICE_ENTERPRISE_USD   = os.environ.get('STRIPE_PRICE_ENTERPRISE_USD')
    STRIPE_PRICE_ENTERPRISE_EUR   = os.environ.get('STRIPE_PRICE_ENTERPRISE_EUR')
    STRIPE_PRICE_ENTERPRISE_JPY   = os.environ.get('STRIPE_PRICE_ENTERPRISE_JPY')
    GOOGLE_CLIENT_ID     = os.environ.get('GOOGLE_CLIENT_ID')
    GOOGLE_CLIENT_SECRET = os.environ.get('GOOGLE_CLIENT_SECRET')
    GOOGLE_REDIRECT_URI  = os.environ.get('GOOGLE_REDIRECT_URI', 'http://localhost:5001/api/auth/google/callback')
    GOOGLE_DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration'
    STRIPE_SUCCESS_URL            = os.environ.get('STRIPE_SUCCESS_URL', 'http://localhost:5000/dashboard?payment=success')
    STRIPE_CANCEL_URL             = os.environ.get('STRIPE_CANCEL_URL', 'http://localhost:5000/pricing?payment=cancelled')
    PLAN_SCAN_LIMITS              = {'free': 5, 'professional': None, 'enterprise': None}
    API_ACCESS_PLANS              = {'enterprise'}


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "sqlite:///aipet_dev.db"
    )


class ProductionConfig(Config):
    DEBUG = False
    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", ""
    ).replace("postgres://", "postgresql://")


class TestingConfig(Config):
    TESTING = True
    SQLALCHEMY_DATABASE_URI = "sqlite:///aipet_test.db"


config = {
    "development": DevelopmentConfig,
    "production":  ProductionConfig,
    "testing":     TestingConfig,
    "default":     DevelopmentConfig,
}