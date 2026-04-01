# Security Policy

## Reporting a Vulnerability

To report a security vulnerability, please open a GitHub issue
or contact the maintainer directly.

## Known Development Dependency Vulnerabilities

The following vulnerabilities exist in development-only packages
(react-scripts, webpack-dev-server, jest) and do NOT affect the
production build:

- nth-check — development tool only
- postcss — development tool only  
- serialize-javascript — development tool only
- webpack-dev-server — development tool only

These packages are not included in the production build (npm run build).
All production Python dependencies are fully patched as of April 2026.

## Production Security Measures

- JWT authentication with expiry
- bcrypt password hashing
- SHA-256 API key hashing
- Rate limiting on all endpoints
- CORS restricted to approved origins
- Stripe webhook signature verification
- SQL injection prevention via SQLAlchemy ORM
- Security headers on all responses
- Brute force protection on login
