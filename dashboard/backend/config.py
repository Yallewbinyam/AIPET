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
    RATELIMIT_STORAGE_URI         = "memory://"

    # Stripe
    STRIPE_SECRET_KEY             = os.environ.get('STRIPE_SECRET_KEY')
    STRIPE_PUBLISHABLE_KEY        = os.environ.get('STRIPE_PUBLISHABLE_KEY')
    STRIPE_WEBHOOK_SECRET         = os.environ.get('STRIPE_WEBHOOK_SECRET')
    STRIPE_PRICE_PROFESSIONAL     = os.environ.get('STRIPE_PRICE_PROFESSIONAL')
    STRIPE_PRICE_ENTERPRISE       = os.environ.get('STRIPE_PRICE_ENTERPRISE')
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