import stripe
from datetime import datetime, timezone
from flask import Blueprint, request, jsonify, current_app
from flask_jwt_extended import jwt_required, get_jwt_identity

from ..models import User, db
from .stripe_client import get_stripe


payments_bp = Blueprint('payments', __name__)


@payments_bp.route('/create-checkout-session', methods=['POST'])
@jwt_required()
def create_checkout_session():
    stripe = get_stripe()

    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))
    

    if not user:
        return jsonify({'error': 'User not found'}), 404

    data = request.get_json()
    plan = data.get('plan')

    if plan not in ('professional', 'enterprise', 'aipet_x'):
        return jsonify({'error': 'Invalid plan'}), 400

    data_currency = data.get('currency', 'gbp').lower()
    if data_currency not in ('gbp', 'usd', 'eur', 'jpy'):
        data_currency = 'gbp'

    price_map = {
        'professional': {
            'gbp': current_app.config['STRIPE_PRICE_PROFESSIONAL'],
            'usd': current_app.config['STRIPE_PRICE_PROFESSIONAL_USD'],
            'eur': current_app.config['STRIPE_PRICE_PROFESSIONAL_EUR'],
            'jpy': current_app.config['STRIPE_PRICE_PROFESSIONAL_JPY'],
        },
        'enterprise': {
            'gbp': current_app.config['STRIPE_PRICE_ENTERPRISE'],
            'usd': current_app.config['STRIPE_PRICE_ENTERPRISE_USD'],
            'eur': current_app.config['STRIPE_PRICE_ENTERPRISE_EUR'],
            'jpy': current_app.config['STRIPE_PRICE_ENTERPRISE_JPY'],
        },
        'aipet_x': {
            'gbp': current_app.config['STRIPE_PRICE_AIPET_X'],
            'usd': current_app.config['STRIPE_PRICE_AIPET_X_USD'],
            'eur': current_app.config['STRIPE_PRICE_AIPET_X_EUR'],
            'jpy': current_app.config['STRIPE_PRICE_AIPET_X_JPY'],
        },
    }
    price_id = price_map[plan][data_currency]

    try:
        customer_id = user.stripe_customer_id

        if not customer_id:
            customer = stripe.Customer.create(
                email=user.email,
                metadata={'aipet_user_id': user.id}
            )
            customer_id = customer.id
            user.stripe_customer_id = customer_id
            db.session.commit()

        session = stripe.checkout.Session.create(
            customer=customer_id,
            mode='subscription',
            line_items=[{'price': price_id, 'quantity': 1}],
            success_url=(
                current_app.config['STRIPE_SUCCESS_URL']
                + '&session_id={CHECKOUT_SESSION_ID}'
            ),
            cancel_url=current_app.config['STRIPE_CANCEL_URL'],
            metadata={'aipet_user_id': str(user.id), 'plan': plan},
            allow_promotion_codes=True,
        )

        return jsonify({'checkout_url': session.url}), 200

    except stripe.error.StripeError as e:
        current_app.logger.error(f'Stripe error: {e}')
        return jsonify({'error': 'Payment service unavailable'}), 503




@payments_bp.route('/detect-currency', methods=['GET'])
def detect_currency():
    import requests as req
    country_to_currency = {
        'GB': 'GBP', 'US': 'USD', 'CA': 'USD', 'AU': 'USD',
        'DE': 'EUR', 'FR': 'EUR', 'IT': 'EUR', 'ES': 'EUR',
        'NL': 'EUR', 'BE': 'EUR', 'AT': 'EUR', 'PT': 'EUR',
        'FI': 'EUR', 'IE': 'EUR', 'GR': 'EUR', 'JP': 'JPY',
    }
    symbols = {'GBP': '£', 'USD': '$', 'EUR': '€', 'JPY': '¥'}
    try:
        ip = request.headers.get('X-Forwarded-For', request.remote_addr)
        ip = ip.split(',')[0].strip()
        if ip in ('127.0.0.1', '::1', 'localhost'):
            currency = 'GBP'
        else:
            r = req.get(f'https://ipapi.co/{ip}/country/', timeout=3)
            country = r.text.strip()
            currency = country_to_currency.get(country, 'GBP')
    except Exception:
        currency = 'GBP'
    return jsonify({
        'currency': currency,
        'symbol': symbols.get(currency, '£')
    }), 200


@payments_bp.route('/webhook', methods=['POST'])
def stripe_webhook():
    stripe_sdk = get_stripe()
    payload = request.get_data(as_text=False)
    sig_header = request.headers.get('Stripe-Signature')

    if not sig_header:
        return jsonify({'error': 'Missing signature'}), 400

    try:
        event = stripe_sdk.Webhook.construct_event(
            payload,
            sig_header,
            current_app.config['STRIPE_WEBHOOK_SECRET']
        )
    except ValueError:
        return jsonify({'error': 'Invalid payload'}), 400
    except stripe.error.SignatureVerificationError:
        return jsonify({'error': 'Invalid signature'}), 400

    event_type = event['type']

    if event_type == 'checkout.session.completed':
        _handle_checkout_completed(event['data']['object'])
    elif event_type == 'customer.subscription.updated':
        _handle_subscription_updated(event['data']['object'])
    elif event_type == 'customer.subscription.deleted':
        _handle_subscription_deleted(event['data']['object'])

    return jsonify({'status': 'received'}), 200


def _handle_checkout_completed(session):
    plan = session.get('metadata', {}).get('plan')
    stripe_customer_id = session.get('customer')
    subscription_id = session.get('subscription')

    if not all([plan, stripe_customer_id, subscription_id]):
        return

    user = User.query.filter_by(stripe_customer_id=stripe_customer_id).first()

    if not user:
        return

    user.plan = plan
    user.stripe_subscription_id = subscription_id

    stripe_sdk = get_stripe()
    subscription = stripe_sdk.Subscription.retrieve(subscription_id)
    period_end_ts = subscription.get('current_period_end')

    if period_end_ts:
        user.plan_expires_at = datetime.fromtimestamp(
            period_end_ts, tz=timezone.utc
        )

    db.session.commit()


def _handle_subscription_updated(subscription):
    sub_id = subscription.get('id')
    user = User.query.filter_by(stripe_subscription_id=sub_id).first()

    if not user:
        return

    period_end_ts = subscription.get('current_period_end')
    if period_end_ts:
        user.plan_expires_at = datetime.fromtimestamp(
            period_end_ts, tz=timezone.utc
        )

    db.session.commit()


def _handle_subscription_deleted(subscription):
    sub_id = subscription.get('id')
    user = User.query.filter_by(stripe_subscription_id=sub_id).first()

    if not user:
        return

    user.plan = 'free'
    user.stripe_subscription_id = None
    user.plan_expires_at = None
    db.session.commit()


@payments_bp.route('/subscription', methods=['GET'])
@jwt_required()
def get_subscription():
    user_id = get_jwt_identity()
    user = User.query.get(int(user_id))

    if not user:
        return jsonify({'error': 'User not found'}), 404

    return jsonify({
        'plan':           user.plan,
        'scan_limit':     user.scan_limit,
        'has_api_access': user.has_api_access,
        'plan_expires_at': (
            user.plan_expires_at.isoformat()
            if user.plan_expires_at else None
        ),
    }), 200


@payments_bp.route('/portal', methods=['POST'])
@jwt_required()
def billing_portal():
    stripe_sdk = get_stripe()
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.stripe_customer_id:
        return jsonify({'error': 'No billing account found'}), 400

    try:
        portal_session = stripe_sdk.billing_portal.Session.create(
            customer=user.stripe_customer_id,
            return_url=current_app.config['STRIPE_SUCCESS_URL'],
        )
        return jsonify({'portal_url': portal_session.url}), 200

    except stripe.error.StripeError as e:
        return jsonify({'error': 'Could not open billing portal'}), 503


@payments_bp.route('/cancel', methods=['POST'])
@jwt_required()
def cancel_subscription():
    stripe_sdk = get_stripe()
    current_user_email = get_jwt_identity()
    user = User.query.filter_by(email=current_user_email).first()

    if not user:
        return jsonify({'error': 'User not found'}), 404

    if not user.stripe_subscription_id:
        return jsonify({'error': 'No active subscription'}), 400

    try:
        stripe_sdk.Subscription.modify(
            user.stripe_subscription_id,
            cancel_at_period_end=True
        )
        return jsonify({'message': 'Subscription will cancel at end of period'}), 200

    except stripe.error.StripeError as e:
        return jsonify({'error': 'Could not cancel subscription'}), 503


def check_scan_limit(user):
    if user.scan_limit is None:
        return True, 'ok'

    used = _count_scans_this_month(user.id)

    if used >= user.scan_limit:
        return False, (
            f'Monthly scan limit reached ({used}/{user.scan_limit}). '
            f'Upgrade to Professional for unlimited scans.'
        )

    return True, 'ok'


def _count_scans_this_month(user_id):
    from ..models import ScanJob

    now = datetime.now(timezone.utc)
    month_start = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)

    return ScanJob.query.filter(
        ScanJob.user_id == user_id,
        ScanJob.created_at >= month_start,
    ).count()