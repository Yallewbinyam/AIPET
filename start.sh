#!/bin/bash
cd /home/binyam/AIPET
source venv/bin/activate

# Kill any existing Flask process
pkill -f app_cloud.py 2>/dev/null
sleep 1

export DATABASE_URL=postgresql://aipet_user:aipet_password@localhost:5433/aipet_db
export JWT_SECRET_KEY=$(grep JWT_SECRET_KEY .env | cut -d= -f2)
export SECRET_KEY=$(grep ^SECRET_KEY .env | cut -d= -f2)
export ANTHROPIC_API_KEY=$(grep ANTHROPIC_API_KEY .env | cut -d= -f2)
export STRIPE_SECRET_KEY=$(grep STRIPE_SECRET_KEY .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL=$(grep ^STRIPE_PRICE_PROFESSIONAL= .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE=$(grep ^STRIPE_PRICE_ENTERPRISE= .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL_USD=$(grep STRIPE_PRICE_PROFESSIONAL_USD .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL_EUR=$(grep STRIPE_PRICE_PROFESSIONAL_EUR .env | cut -d= -f2)
export STRIPE_PRICE_PROFESSIONAL_JPY=$(grep STRIPE_PRICE_PROFESSIONAL_JPY .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE_USD=$(grep STRIPE_PRICE_ENTERPRISE_USD .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE_EUR=$(grep STRIPE_PRICE_ENTERPRISE_EUR .env | cut -d= -f2)
export STRIPE_PRICE_ENTERPRISE_JPY=$(grep STRIPE_PRICE_ENTERPRISE_JPY .env | cut -d= -f2)
export STRIPE_WEBHOOK_SECRET=$(grep STRIPE_WEBHOOK_SECRET .env | cut -d= -f2)
export ALERT_EMAIL=$(grep ALERT_EMAIL .env | cut -d= -f2)
export SMTP_USER=$(grep SMTP_USER .env | cut -d= -f2)
export SMTP_PASSWORD=$(grep SMTP_PASSWORD .env | cut -d= -f2)
export GOOGLE_CLIENT_ID=$(grep GOOGLE_CLIENT_ID .env | cut -d= -f2)
export GOOGLE_CLIENT_SECRET=$(grep GOOGLE_CLIENT_SECRET .env | cut -d= -f2)
export GOOGLE_REDIRECT_URI=$(grep GOOGLE_REDIRECT_URI .env | cut -d= -f2)

echo "Starting AIPET Cloud..."
python dashboard/backend/app_cloud.py
