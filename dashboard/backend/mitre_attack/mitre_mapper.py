"""
AIPET X — MITRE ATT&CK Central Mapper

Source-aware mapping functions that translate detection signals from each
capability into ATT&CK technique IDs.  All functions return lists of
TechniqueMapping dicts.  aggregate_techniques() merges them into the
final response payload.

Every mapping records:
  - which source generated it (ml_feature, behavioral, kev, otx)
  - the input that triggered the mapping (e.g. "failed_auth_rate=0.30")
  - the confidence level (high/medium/low)

No live API calls — all mappings use the local TECHNIQUE_CATALOG.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import TypedDict

from dashboard.backend.mitre_attack.catalog import (
    TECHNIQUE_CATALOG,
    ML_FEATURE_TO_TECHNIQUE,
    BEHAVIORAL_ANOMALY_TO_TECHNIQUE,
    CWE_TO_TECHNIQUE,
    OTX_INDICATOR_TO_TECHNIQUE,
    OTX_TAG_TO_TECHNIQUE,
)

_CONF_RANK = {"high": 3, "medium": 2, "low": 1}


class TechniqueMapping(TypedDict):
    technique_id: str
    confidence:   str    # "high" | "medium" | "low"
    reason:       str    # human-readable explanation
    source:       str    # "ml_feature" | "behavioral" | "kev" | "otx"


def from_ml_features(top_contributors: list[dict]) -> list[TechniqueMapping]:
    """
    Map the top SHAP contributors from an Isolation Forest detection to techniques.
    Considers only the top 5 contributors (by absolute SHAP value) to avoid noise.
    Only maps features that increase anomaly score (direction="increases_anomaly").
    """
    mappings: list[TechniqueMapping] = []
    seen: dict[str, TechniqueMapping] = {}

    ranked = sorted(top_contributors, key=lambda c: -abs(c.get("shap_value", 0)))[:5]
    for contrib in ranked:
        feature   = contrib.get("feature", "")
        direction = contrib.get("direction", "")
        shap_val  = contrib.get("shap_value", 0.0)
        raw_val   = contrib.get("raw_value", "")

        if direction != "increases_anomaly":
            continue

        entry = ML_FEATURE_TO_TECHNIQUE.get(feature)
        if not entry:
            continue

        technique_id, confidence = entry
        reason = (
            f"{feature}={round(float(raw_val), 3) if raw_val != '' else '?'} "
            f"(SHAP={round(shap_val, 3)}) increases anomaly score"
        )

        existing = seen.get(technique_id)
        if existing is None or _CONF_RANK[confidence] > _CONF_RANK[existing["confidence"]]:
            seen[technique_id] = TechniqueMapping(
                technique_id=technique_id,
                confidence=confidence,
                reason=reason,
                source="ml_feature",
            )

    return list(seen.values())


def from_behavioral_deviations(top_deviations: list[dict]) -> list[TechniqueMapping]:
    """
    Map the top Z-score deviations from a per-device baseline check to techniques.
    Used by device_deviation_detector.py to replace the hardcoded T1071 assignment.
    """
    mappings: list[TechniqueMapping] = []
    seen: dict[str, TechniqueMapping] = {}

    ranked = sorted(top_deviations, key=lambda d: -d.get("z_score", 0))[:5]
    for dev in ranked:
        feature = dev.get("feature", "")
        z_score = dev.get("z_score", 0.0)

        entry = ML_FEATURE_TO_TECHNIQUE.get(feature)
        if not entry:
            continue

        technique_id, base_conf = entry
        # Boost confidence for extreme deviations
        if z_score >= 5.0 and base_conf == "medium":
            confidence = "high"
        elif z_score < 2.0 and base_conf == "high":
            confidence = "medium"
        else:
            confidence = base_conf

        reason = f"{feature} deviates {z_score:.1f}σ from baseline"

        existing = seen.get(technique_id)
        if existing is None or _CONF_RANK[confidence] > _CONF_RANK[existing["confidence"]]:
            seen[technique_id] = TechniqueMapping(
                technique_id=technique_id,
                confidence=confidence,
                reason=reason,
                source="behavioral",
            )

    return list(seen.values())


def from_behavioral_anomaly(
    anomaly_type: str,
    top_deviations: list[dict] | None = None,
) -> list[TechniqueMapping]:
    """
    Map a behavioral anomaly_type to its technique.
    If top_deviations provided, adds feature-level mappings for more specificity.
    """
    mappings: list[TechniqueMapping] = []

    entry = BEHAVIORAL_ANOMALY_TO_TECHNIQUE.get(anomaly_type)
    if entry:
        technique_id, confidence = entry
        mappings.append(TechniqueMapping(
            technique_id=technique_id,
            confidence=confidence,
            reason=f"behavioral anomaly_type={anomaly_type}",
            source="behavioral",
        ))

    if top_deviations:
        mappings.extend(from_behavioral_deviations(top_deviations))

    return mappings


def from_kev_hit(cve_id: str, cwes: list[str] | None = None) -> list[TechniqueMapping]:
    """
    Map a CISA KEV hit to techniques via its CWEs.
    Falls back to T1190 (Exploit Public-Facing Application) with low confidence
    when no CWE data is available.
    """
    mappings: list[TechniqueMapping] = []
    seen: set[str] = set()

    if cwes:
        for cwe in cwes:
            # CWEs from kev_catalog are stored as bare strings like "CWE-77"
            cwe_key = cwe if cwe.startswith("CWE-") else f"CWE-{cwe}"
            entry = CWE_TO_TECHNIQUE.get(cwe_key)
            if entry and entry[0] not in seen:
                technique_id, confidence = entry
                seen.add(technique_id)
                mappings.append(TechniqueMapping(
                    technique_id=technique_id,
                    confidence=confidence,
                    reason=f"KEV entry {cve_id} has {cwe_key}",
                    source="kev",
                ))

    if not mappings:
        mappings.append(TechniqueMapping(
            technique_id="T1190",
            confidence="low",
            reason=f"KEV entry {cve_id} — fallback (no CWE data available)",
            source="kev",
        ))

    return mappings


def from_otx_match(
    indicator_type: str,
    tags: list[str] | None = None,
) -> list[TechniqueMapping]:
    """
    Map an OTX IOC match to techniques.
    OTX cache has no per-pulse technique IDs; uses indicator-type heuristics
    and tag-based overrides.
    """
    # Tag-based override (more specific)
    if tags:
        for tag in [t.lower().strip() for t in tags]:
            entry = OTX_TAG_TO_TECHNIQUE.get(tag)
            if entry:
                technique_id, confidence = entry
                return [TechniqueMapping(
                    technique_id=technique_id,
                    confidence=confidence,
                    reason=f"OTX indicator tagged '{tag}'",
                    source="otx",
                )]

    # Fallback to indicator-type heuristic
    ioc_type = (indicator_type or "").lower()
    # Normalise: "IPv4"/"IPv6" → "ip", "FileHash-*" → "hash", etc.
    if ioc_type in ("ipv4", "ipv6"):
        ioc_type = "ip"
    elif ioc_type.startswith("filehash") or ioc_type in ("md5", "sha1", "sha256"):
        ioc_type = "hash"

    entry = OTX_INDICATOR_TO_TECHNIQUE.get(ioc_type, OTX_INDICATOR_TO_TECHNIQUE.get("ip"))
    if entry:
        technique_id, confidence = entry
        return [TechniqueMapping(
            technique_id=technique_id,
            confidence=confidence,
            reason=f"OTX indicator type={indicator_type}",
            source="otx",
        )]

    return []


def aggregate_techniques(mappings: list[TechniqueMapping]) -> list[dict]:
    """
    Merge per-source mappings into a deduplicated list enriched from TECHNIQUE_CATALOG.

    Deduplication keeps the highest-confidence entry per technique_id and
    collects all source labels and reasons.  Returns at most 10 techniques,
    sorted: highest confidence first, then by technique_id.
    """
    merged: dict[str, dict] = {}

    for m in mappings:
        tid = m["technique_id"]
        if tid not in merged:
            merged[tid] = {
                "technique_id": tid,
                "confidence":   m["confidence"],
                "sources":      [m["source"]],
                "reasons":      [m["reason"]],
            }
        else:
            existing = merged[tid]
            if _CONF_RANK[m["confidence"]] > _CONF_RANK[existing["confidence"]]:
                existing["confidence"] = m["confidence"]
            if m["source"] not in existing["sources"]:
                existing["sources"].append(m["source"])
            if m["reason"] not in existing["reasons"]:
                existing["reasons"].append(m["reason"])

    # Enrich with catalog metadata
    result = []
    for tid, entry in merged.items():
        cat = TECHNIQUE_CATALOG.get(tid, {})
        result.append({
            "technique_id":  tid,
            "name":          cat.get("name", tid),
            "tactic":        cat.get("tactic", "Unknown"),
            "tactic_id":     cat.get("tactic_id", ""),
            "url":           cat.get("url", f"https://attack.mitre.org/techniques/{tid.replace('.', '/')}/"),
            "confidence":    entry["confidence"],
            "sources":       entry["sources"],
            "reasons":       entry["reasons"],
        })

    # Sort: high confidence first, then alphabetically by technique_id
    result.sort(key=lambda x: (-_CONF_RANK[x["confidence"]], x["technique_id"]))
    return result[:10]
