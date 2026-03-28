# =============================================================
# AIPET Cloud — Configuration
# =============================================================
import os
from dotenv import load_dotenv

load_dotenv()

class Config:
    SECRET_KEY         = os.environ.get("SECRET_KEY", "aipet-change-in-production")
    JWT_SECRET_KEY     = os.environ.get("JWT_SECRET_KEY", "aipet-jwt-change-in-production")
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    RATELIMIT_STORAGE_URI = "memory://"

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
