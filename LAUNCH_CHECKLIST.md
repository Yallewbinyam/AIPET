# AIPET Cloud — Launch Checklist
## Complete before going live at aipet.io

---

## 1. Infrastructure
- [ ] DigitalOcean droplet created (Ubuntu 24.04, 2GB RAM)
- [ ] Domain aipet.io purchased and DNS configured
- [ ] SSL certificate installed (Let's Encrypt)
- [ ] Firewall configured (ports 80, 443, 22 only)
- [ ] SSH key authentication enabled

## 2. Application
- [ ] Code cloned from GitHub on server
- [ ] Virtual environment created and dependencies installed
- [ ] Production `.env` configured with live secrets
- [ ] Database created and migrations run
- [ ] React production build created (`npm run build`)
- [ ] Nginx configured and running
- [ ] Gunicorn configured and running
- [ ] All systemd services enabled and running

## 3. Security
- [ ] Security audit passing 13/13 (`bash scripts/security_audit.sh`)
- [ ] All Python dependencies patched (`pip-audit`)
- [ ] Strong JWT secret key set (32+ chars)
- [ ] Strong database password set
- [ ] HTTPS enforced — HTTP redirects to HTTPS
- [ ] CORS configured for aipet.io only
- [ ] Rate limiting active on all endpoints

## 4. Payments
- [ ] Stripe switched to LIVE mode (sk_live_...)
- [ ] Live products created in Stripe dashboard
- [ ] Live price IDs in production .env
- [ ] Webhook endpoint updated to https://aipet.io/payments/webhook
- [ ] Test payment completed with real card
- [ ] Subscription upgrade verified end-to-end
- [ ] Webhook events verified in Stripe dashboard

## 5. Monitoring
- [ ] Health monitor service running (systemd)
- [ ] Email alerts configured and tested
- [ ] Log files being written (/var/log/aipet/)
- [ ] Daily database backup cron job active
- [ ] First backup verified and restore tested
- [ ] UptimeRobot monitoring configured for aipet.io

## 6. Functionality
- [ ] Landing page loads at https://aipet.io
- [ ] User registration works
- [ ] User login works
- [ ] Demo scan completes successfully
- [ ] Findings displayed correctly
- [ ] AI analysis displayed correctly
- [ ] Reports downloadable
- [ ] Pricing page loads correctly
- [ ] Billing page shows correct plan
- [ ] API key generation works (Enterprise)
- [ ] API key authentication works on scan endpoint
- [ ] Sign out works

## 7. Documentation
- [ ] README.md updated with live URL
- [ ] INSTALL.md updated with production setup
- [ ] USER_MANUAL.md reviewed and accurate
- [ ] SECURITY.md published
- [ ] GitHub repository public and professional

## 8. Legal (UK)
- [ ] Privacy Policy published
- [ ] Terms of Service published
- [ ] Cookie policy published
- [ ] GDPR compliance reviewed
- [ ] ICO registration completed (if processing personal data)

## 9. Launch
- [ ] Version tagged as v2.0.0 in GitHub
- [ ] LinkedIn announcement drafted
- [ ] First 10 potential customers identified
- [ ] Coventry University supervisor informed
- [ ] GitHub README updated with live demo link

---

**Sign off:** All items above checked before public launch.

*AIPET Cloud v2.0.0*