"""
AIPET X — Marketplace Models

Three tables:
  mp_plugins   — available plugins in the marketplace
  mp_installs  — which plugins each user has installed
  mp_reviews   — user ratings and reviews for plugins
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class MpPlugin(db.Model):
    """
    A plugin available in the AIPET X Marketplace.

    category:    integration | scan_module | report_template |
                 ai_pack | threat_feed | dashboard_widget
    publisher:   who built this plugin
    verified:    True = officially verified by AIPET team
    free:        True = free, False = paid
    install_count: how many times installed
    avg_rating:  average star rating (1-5)
    """
    __tablename__ = "mp_plugins"

    id            = db.Column(db.Integer,     primary_key=True)
    name          = db.Column(db.String(200), nullable=False)
    slug          = db.Column(db.String(100), nullable=False, unique=True)
    description   = db.Column(db.Text,        nullable=True)
    long_desc     = db.Column(db.Text,        nullable=True)
    category      = db.Column(db.String(50),  nullable=False)
    publisher     = db.Column(db.String(200), nullable=False)
    version       = db.Column(db.String(20),  default="1.0.0")
    icon          = db.Column(db.String(10),  default="🔌")
    tags          = db.Column(db.Text,        nullable=True)   # JSON list
    verified      = db.Column(db.Boolean,     default=False)
    free          = db.Column(db.Boolean,     default=True)
    price_gbp     = db.Column(db.Float,       default=0.0)
    install_count = db.Column(db.Integer,     default=0)
    avg_rating    = db.Column(db.Float,       default=0.0)
    review_count  = db.Column(db.Integer,     default=0)
    active        = db.Column(db.Boolean,     default=True)
    created_at    = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":            self.id,
            "name":          self.name,
            "slug":          self.slug,
            "description":   self.description,
            "long_desc":     self.long_desc,
            "category":      self.category,
            "publisher":     self.publisher,
            "version":       self.version,
            "icon":          self.icon,
            "tags":          self.tags,
            "verified":      self.verified,
            "free":          self.free,
            "price_gbp":     self.price_gbp,
            "install_count": self.install_count,
            "avg_rating":    self.avg_rating,
            "review_count":  self.review_count,
            "created_at":    str(self.created_at),
        }


class MpInstall(db.Model):
    """
    Records when a user installs a plugin.
    One record per user per plugin.
    """
    __tablename__ = "mp_installs"

    id         = db.Column(db.Integer,  primary_key=True)
    plugin_id  = db.Column(db.Integer,  db.ForeignKey("mp_plugins.id"), nullable=False)
    user_id    = db.Column(db.Integer,  db.ForeignKey("users.id"),      nullable=False)
    config     = db.Column(db.Text,     nullable=True)   # JSON plugin config
    enabled    = db.Column(db.Boolean,  default=True)
    installed_at=db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":           self.id,
            "plugin_id":    self.plugin_id,
            "user_id":      self.user_id,
            "config":       self.config,
            "enabled":      self.enabled,
            "installed_at": str(self.installed_at),
        }


class MpReview(db.Model):
    """
    A user rating and review for a marketplace plugin.
    One review per user per plugin.
    """
    __tablename__ = "mp_reviews"

    id         = db.Column(db.Integer,     primary_key=True)
    plugin_id  = db.Column(db.Integer,     db.ForeignKey("mp_plugins.id"), nullable=False)
    user_id    = db.Column(db.Integer,     db.ForeignKey("users.id"),      nullable=False)
    rating     = db.Column(db.Integer,     nullable=False)   # 1-5 stars
    review     = db.Column(db.Text,        nullable=True)
    created_at = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":         self.id,
            "plugin_id":  self.plugin_id,
            "user_id":    self.user_id,
            "rating":     self.rating,
            "review":     self.review,
            "created_at": str(self.created_at),
        }
