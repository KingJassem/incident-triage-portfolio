"""Deterministic incident intake, validation, classification, and human escalation.

No external APIs, production credentials, or automated containment actions.
"""
from __future__ import annotations

from datetime import datetime, timezone
from hashlib import sha256
import json
from pathlib import Path
import re
from typing import Any

CATEGORIES = {"authentication", "phishing", "endpoint", "connectivity"}
SIGNALS = {"failed_logins", "impossible_travel", "suspicious_link", "malware_alert", "offline", "routine"}
SEVERITIES = ("low", "medium", "high")
_ID = re.compile(r"^[A-Za-z0-9_-]{3,64}$")
_ALIAS = re.compile(r"^[A-Za-z0-9_.-]{2,48}$")


class ValidationError(ValueError):
    pass


def validate_event(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise ValidationError("Expected JSON object")
    required = {"event_id", "observed_at", "source", "category", "signal", "account_alias"}
    missing = sorted(required - payload.keys())
    if missing:
        raise ValidationError("Missing fields: " + ", ".join(missing))
    extra = sorted(payload.keys() - required)
    if extra:
        raise ValidationError("Unsupported fields: " + ", ".join(extra))
    event_id, alias = payload["event_id"], payload["account_alias"]
    if not isinstance(event_id, str) or not _ID.fullmatch(event_id):
        raise ValidationError("event_id must be 3-64 safe characters")
    if not isinstance(alias, str) or not _ALIAS.fullmatch(alias):
        raise ValidationError("account_alias must be a pseudonymous identifier")
    if not isinstance(payload["category"], str) or not isinstance(payload["signal"], str) or payload["category"] not in CATEGORIES or payload["signal"] not in SIGNALS:
        raise ValidationError("Unsupported category or signal")
    source = payload["source"]
    if not isinstance(source, str) or source not in {"helpdesk", "endpoint_monitor", "identity_monitor"}:
        raise ValidationError("Unsupported source")
    timestamp = payload["observed_at"]
    if not isinstance(timestamp, str):
        raise ValidationError("observed_at must be an ISO 8601 string")
    try:
        dt = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError("Invalid observed_at timestamp") from exc
    if dt.tzinfo is None:
        raise ValidationError("Timestamp must include a timezone")
    return {**payload, "observed_at": dt.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")}


def assess(payload: Any) -> dict[str, Any]:
    event = validate_event(payload)
    signal = event["signal"]
    category = event["category"]
    explanations: list[str] = []
    severity = "low"
    if category == "authentication" and signal == "impossible_travel":
        severity = "high"
        explanations.append("Identity anomaly needs analyst validation; signal alone does not prove compromise")
    elif category == "phishing" and signal == "suspicious_link":
        severity = "high"
        explanations.append("Suspicious link reported; do not click or execute it")
    elif category == "endpoint" and signal == "malware_alert":
        severity = "high"
        explanations.append("Endpoint alert needs evidence review before containment decisions")
    elif category == "authentication" and signal == "failed_logins":
        severity = "medium"
        explanations.append("Authentication failures warrant context and log review")
    elif signal == "offline":
        severity = "medium"
        explanations.append("Check scope, connectivity and service health before escalating")
    else:
        explanations.append("No high-confidence indicator in this limited demonstration")

    if (category, signal) not in {
        ("authentication", "impossible_travel"), ("authentication", "failed_logins"),
        ("phishing", "suspicious_link"), ("endpoint", "malware_alert"),
        ("connectivity", "offline"),
        ("authentication", "routine"), ("connectivity", "routine"),
        ("endpoint", "routine"), ("phishing", "routine")
    }:
        raise ValidationError("Incompatible category and signal")
    return {
        "event_id": event["event_id"],
        "observed_at": event["observed_at"],
        "severity": severity,
        "human_review_required": severity in {"medium", "high"},
        "recommended_action": {
            "high": "Escalate to authorized security analyst; preserve evidence, do not self-contain",
            "medium": "Request additional context and assign to support/security queue",
            "low": "Document and follow standard support workflow",
        }[severity],
        "rationale": explanations,
        "automation_limit": "Advisory classification only; no account, network, or endpoint modification",
        "fingerprint": sha256(event["event_id"].encode("utf-8")).hexdigest()[:12],
    }


def process_batch(events: list[dict[str, Any]]) -> dict[str, Any]:
    if not isinstance(events, list):
        raise ValidationError("events must be an array")
    seen = set()
    results = []
    duplicates = []
    rejected = []
    for index, item in enumerate(events):
        try:
            validated = validate_event(item)
            identity = validated["event_id"]
            if identity in seen:
                duplicates.append(identity)
                continue
            seen.add(identity)
            results.append(assess(validated))
        except ValidationError as exc:
            rejected.append({"index": index, "reason": str(exc)})
    return {"assessments": results, "duplicate_ids": duplicates, "rejected": rejected,
            "counts": {"accepted": len(results), "duplicates": len(duplicates), "rejected": len(rejected),
                       "human_review": sum(r["human_review_required"] for r in results)}}


def load_samples(path: str | Path) -> list[dict[str, Any]]:
    raw = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(raw, list):
        raise ValidationError("Sample file must contain an array")
    return raw
