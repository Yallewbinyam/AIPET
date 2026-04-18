"""
AIPET X — Supply Chain Security (SBOM) Models

Three tables:
  sc_components  — software components/dependencies
  sc_vulns       — known vulnerabilities per component
  sc_sboms       — generated SBOM reports
"""
from datetime import datetime, timezone
from dashboard.backend.models import db


class ScComponent(db.Model):
    """
    A software component in the supply chain.

    component_type: library | framework | os_package |
                    container | firmware | sdk
    license:        MIT | Apache-2.0 | GPL-3.0 | etc.
    risk_level:     critical | high | medium | low | safe
    """
    __tablename__ = "sc_components"

    id             = db.Column(db.Integer,     primary_key=True)
    name           = db.Column(db.String(200), nullable=False)
    version        = db.Column(db.String(50),  nullable=True)
    component_type = db.Column(db.String(50),  nullable=False)
    ecosystem      = db.Column(db.String(50),  nullable=True)
    license        = db.Column(db.String(100), nullable=True)
    supplier       = db.Column(db.String(200), nullable=True)
    used_in        = db.Column(db.Text,        nullable=True)   # JSON list
    direct_dep     = db.Column(db.Boolean,     default=True)
    vuln_count     = db.Column(db.Integer,     default=0)
    critical_vulns = db.Column(db.Integer,     default=0)
    risk_level     = db.Column(db.String(20),  default="safe")
    license_risk   = db.Column(db.String(20),  default="low")
    last_updated   = db.Column(db.DateTime,    nullable=True)
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        import json
        return {
            "id":             self.id,
            "name":           self.name,
            "version":        self.version,
            "component_type": self.component_type,
            "ecosystem":      self.ecosystem,
            "license":        self.license,
            "supplier":       self.supplier,
            "used_in":        json.loads(self.used_in) if self.used_in else [],
            "direct_dep":     self.direct_dep,
            "vuln_count":     self.vuln_count,
            "critical_vulns": self.critical_vulns,
            "risk_level":     self.risk_level,
            "license_risk":   self.license_risk,
            "last_updated":   str(self.last_updated) if self.last_updated else None,
        }


class ScVuln(db.Model):
    """A known vulnerability in a supply chain component."""
    __tablename__ = "sc_vulns"

    id             = db.Column(db.Integer,     primary_key=True)
    component_id   = db.Column(db.Integer,     db.ForeignKey("sc_components.id"), nullable=False)
    cve_id         = db.Column(db.String(50),  nullable=False)
    severity       = db.Column(db.String(20),  default="Medium")
    cvss_score     = db.Column(db.Float,       default=0.0)
    title          = db.Column(db.String(300), nullable=False)
    description    = db.Column(db.Text,        nullable=True)
    fixed_version  = db.Column(db.String(50),  nullable=True)
    exploit_public = db.Column(db.Boolean,     default=False)
    cisa_kev       = db.Column(db.Boolean,     default=False)
    status         = db.Column(db.String(30),  default="open")
    created_at     = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":             self.id,
            "component_id":   self.component_id,
            "cve_id":         self.cve_id,
            "severity":       self.severity,
            "cvss_score":     self.cvss_score,
            "title":          self.title,
            "description":    self.description,
            "fixed_version":  self.fixed_version,
            "exploit_public": self.exploit_public,
            "cisa_kev":       self.cisa_kev,
            "status":         self.status,
            "created_at":     str(self.created_at),
        }


class ScSbom(db.Model):
    """A generated SBOM report."""
    __tablename__ = "sc_sboms"

    id              = db.Column(db.Integer,     primary_key=True)
    name            = db.Column(db.String(200), nullable=False)
    format          = db.Column(db.String(50),  default="CycloneDX")
    version         = db.Column(db.String(20),  default="1.4")
    components_count= db.Column(db.Integer,     default=0)
    vuln_count      = db.Column(db.Integer,     default=0)
    content         = db.Column(db.Text,        nullable=True)
    created_at      = db.Column(db.DateTime,    default=lambda: datetime.now(timezone.utc))

    def to_dict(self):
        return {
            "id":               self.id,
            "name":             self.name,
            "format":           self.format,
            "version":          self.version,
            "components_count": self.components_count,
            "vuln_count":       self.vuln_count,
            "created_at":       str(self.created_at),
        }
