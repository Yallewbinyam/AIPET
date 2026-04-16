"""
AIPET X — Marketplace Routes

Endpoints:
  GET  /api/marketplace/plugins          — browse all plugins
  GET  /api/marketplace/plugins/<slug>   — plugin detail
  POST /api/marketplace/install/<id>     — install plugin
  DEL  /api/marketplace/install/<id>     — uninstall plugin
  GET  /api/marketplace/installed        — user installed plugins
  POST /api/marketplace/review/<id>      — submit review
  POST /api/marketplace/submit           — submit new plugin
  GET  /api/marketplace/stats            — marketplace metrics
"""
import json
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from dashboard.backend.models import db
from dashboard.backend.marketplace.models import MpPlugin, MpInstall, MpReview

marketplace_bp = Blueprint("marketplace", __name__)


@marketplace_bp.route("/api/marketplace/plugins", methods=["GET"])
@jwt_required()
def list_plugins():
    """Browse all active plugins with optional category filter."""
    category = request.args.get("category")
    search   = request.args.get("search", "").lower()
    sort     = request.args.get("sort", "popular")

    q = MpPlugin.query.filter_by(active=True)
    if category:
        q = q.filter_by(category=category)
    if search:
        q = q.filter(
            MpPlugin.name.ilike(f"%{search}%") |
            MpPlugin.description.ilike(f"%{search}%")
        )
    if sort == "popular":
        q = q.order_by(MpPlugin.install_count.desc())
    elif sort == "rating":
        q = q.order_by(MpPlugin.avg_rating.desc())
    elif sort == "newest":
        q = q.order_by(MpPlugin.created_at.desc())

    plugins = q.all()

    # Mark which ones are installed by this user
    user_id   = int(get_jwt_identity())
    installed = {i.plugin_id for i in MpInstall.query.filter_by(
        user_id=user_id).all()}

    result = []
    for p in plugins:
        d = p.to_dict()
        d["installed"] = p.id in installed
        result.append(d)

    return jsonify({"plugins": result, "total": len(result)})


@marketplace_bp.route("/api/marketplace/plugins/<slug>", methods=["GET"])
@jwt_required()
def plugin_detail(slug):
    """Get full plugin details including reviews."""
    plugin  = MpPlugin.query.filter_by(slug=slug).first_or_404()
    user_id = int(get_jwt_identity())
    install = MpInstall.query.filter_by(
        plugin_id=plugin.id, user_id=user_id).first()
    reviews = MpReview.query.filter_by(
        plugin_id=plugin.id).order_by(
        MpReview.created_at.desc()).limit(10).all()
    data            = plugin.to_dict()
    data["installed"]= install is not None
    data["reviews"]  = [r.to_dict() for r in reviews]
    return jsonify(data)


@marketplace_bp.route("/api/marketplace/install/<int:plugin_id>",
                      methods=["POST"])
@jwt_required()
def install_plugin(plugin_id):
    """Install a plugin for the current user."""
    plugin  = MpPlugin.query.get_or_404(plugin_id)
    user_id = int(get_jwt_identity())

    # Check not already installed
    existing = MpInstall.query.filter_by(
        plugin_id=plugin_id, user_id=user_id).first()
    if existing:
        return jsonify({"error": "Already installed"}), 409

    install = MpInstall(
        plugin_id = plugin_id,
        user_id   = user_id,
        config    = json.dumps({}),
        enabled   = True,
    )
    db.session.add(install)
    plugin.install_count += 1
    db.session.commit()
    return jsonify({"success": True,
                    "install": install.to_dict()}), 201


@marketplace_bp.route("/api/marketplace/install/<int:plugin_id>",
                      methods=["DELETE"])
@jwt_required()
def uninstall_plugin(plugin_id):
    """Uninstall a plugin for the current user."""
    user_id = int(get_jwt_identity())
    install = MpInstall.query.filter_by(
        plugin_id=plugin_id, user_id=user_id).first_or_404()
    plugin  = MpPlugin.query.get(plugin_id)
    if plugin and plugin.install_count > 0:
        plugin.install_count -= 1
    db.session.delete(install)
    db.session.commit()
    return jsonify({"success": True})


@marketplace_bp.route("/api/marketplace/installed", methods=["GET"])
@jwt_required()
def installed_plugins():
    """Get all plugins installed by the current user."""
    user_id  = int(get_jwt_identity())
    installs = MpInstall.query.filter_by(user_id=user_id).all()
    result   = []
    for inst in installs:
        plugin = MpPlugin.query.get(inst.plugin_id)
        if plugin:
            d = plugin.to_dict()
            d["installed"]    = True
            d["enabled"]      = inst.enabled
            d["installed_at"] = str(inst.installed_at)
            result.append(d)
    return jsonify({"plugins": result, "total": len(result)})


@marketplace_bp.route("/api/marketplace/review/<int:plugin_id>",
                      methods=["POST"])
@jwt_required()
def submit_review(plugin_id):
    """Submit a rating and review for a plugin."""
    plugin  = MpPlugin.query.get_or_404(plugin_id)
    user_id = int(get_jwt_identity())
    data    = request.get_json(silent=True) or {}

    if not data.get("rating") or not (1 <= int(data["rating"]) <= 5):
        return jsonify({"error": "rating must be 1-5"}), 400

    # One review per user per plugin
    existing = MpReview.query.filter_by(
        plugin_id=plugin_id, user_id=user_id).first()
    if existing:
        existing.rating = int(data["rating"])
        existing.review = data.get("review", existing.review)
    else:
        review = MpReview(
            plugin_id = plugin_id,
            user_id   = user_id,
            rating    = int(data["rating"]),
            review    = data.get("review"),
        )
        db.session.add(review)
        plugin.review_count += 1

    # Recalculate average rating
    all_reviews  = MpReview.query.filter_by(plugin_id=plugin_id).all()
    plugin.avg_rating = sum(r.rating for r in all_reviews) / len(all_reviews)
    db.session.commit()
    return jsonify({"success": True}), 201


@marketplace_bp.route("/api/marketplace/submit", methods=["POST"])
@jwt_required()
def submit_plugin():
    """
    Submit a new plugin to the marketplace.
    Submitted plugins are created as unverified — pending review.
    """
    data = request.get_json(silent=True) or {}
    required = ["name", "description", "category", "publisher"]
    if not all(k in data for k in required):
        return jsonify({"error": f"Required: {required}"}), 400

    # Generate slug from name
    slug = data["name"].lower().replace(" ", "-").replace("/", "-")
    slug = "".join(c for c in slug if c.isalnum() or c == "-")

    # Ensure unique slug
    existing = MpPlugin.query.filter_by(slug=slug).first()
    if existing:
        slug = f"{slug}-{MpPlugin.query.count() + 1}"

    plugin = MpPlugin(
        name        = data["name"],
        slug        = slug,
        description = data["description"],
        long_desc   = data.get("long_desc"),
        category    = data["category"],
        publisher   = data["publisher"],
        version     = data.get("version", "1.0.0"),
        icon        = data.get("icon", "🔌"),
        tags        = json.dumps(data.get("tags", [])),
        verified    = False,  # Needs review
        free        = data.get("free", True),
        price_gbp   = data.get("price_gbp", 0.0),
        active      = True,
    )
    db.session.add(plugin)
    db.session.commit()
    return jsonify({"success": True,
                    "plugin": plugin.to_dict(),
                    "message": "Plugin submitted — pending verification"}), 201


@marketplace_bp.route("/api/marketplace/stats", methods=["GET"])
@jwt_required()
def marketplace_stats():
    """Marketplace metrics."""
    user_id       = int(get_jwt_identity())
    total_plugins = MpPlugin.query.filter_by(active=True).count()
    verified      = MpPlugin.query.filter_by(
        active=True, verified=True).count()
    total_installs= MpInstall.query.count()
    my_installs   = MpInstall.query.filter_by(user_id=user_id).count()
    total_reviews = MpReview.query.count()

    categories = {}
    for cat in ["integration","scan_module","report_template",
                "ai_pack","threat_feed","dashboard_widget"]:
        categories[cat] = MpPlugin.query.filter_by(
            category=cat, active=True).count()

    top = MpPlugin.query.filter_by(active=True).order_by(
        MpPlugin.install_count.desc()).limit(3).all()

    return jsonify({
        "total_plugins":  total_plugins,
        "verified":       verified,
        "total_installs": total_installs,
        "my_installs":    my_installs,
        "total_reviews":  total_reviews,
        "categories":     categories,
        "top_plugins":    [p.to_dict() for p in top],
    })
