"""Security Command Center (SCC) findings discovery, context enrichment, and criticality triage tool."""

import asyncio
from collections import Counter
from itertools import islice
import json
from google.cloud import securitycenter_v2
from . import get_scc_v2_client

_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CLASS_RANK = {
    "TOXIC_COMBINATION": 5,
    "CHOKEPOINT": 4,
    "THREAT": 3,
    "EXTERNAL_EXPOSURE": 3,
    "EXTENSIVE_EXPOSURE": 3,
    "MISCONFIGURATION": 2,
    "POSTURE_VIOLATION": 2,
    "SCC_ERROR": 1,
}
_FINDING_CLASS_FALLBACK = {10: "EXTERNAL_EXPOSURE"}
_SKIP_PROPS = {"security_marks", "compliance_standards", "scanner_name", "ResourcePath", "ProjectId"}
_SCC_FILTER = 'state="ACTIVE" AND NOT mute="MUTED" AND NOT finding_class="VULNERABILITY"'


def _enum_name(val, fallback: dict | None = None) -> str:
    return getattr(val, "name", (fallback or {}).get(val, str(val or "")))


def _extract_finding_record(result, instance_name: str = "") -> dict:
    f = result.finding
    res = result.resource

    sev_name = _enum_name(f.severity)
    severity = sev_name if sev_name in _SEVERITY_RANK else "LOW"
    raw_display = res.display_name or f.resource_name
    res_display = (
        raw_display.split("/serviceAccounts/")[-1]
        if "/serviceAccounts/" in raw_display
        else raw_display.rstrip("/").split("/")[-1]
    )

    exp = f.attack_exposure
    exposure_score = round(float(exp.score or 0.0), 2) if exp else 0.0
    exposed_resources = {}
    if exp and (
        exp.exposed_high_value_resources_count
        or exp.exposed_medium_value_resources_count
        or exp.exposed_low_value_resources_count
    ):
        exposed_resources = {
            "high_value": int(exp.exposed_high_value_resources_count),
            "medium_value": int(exp.exposed_medium_value_resources_count),
            "low_value": int(exp.exposed_low_value_resources_count),
        }

    iam_context = [
        f"{b.member} -> {b.role}".strip(" ->")
        for b in f.iam_bindings[:3]
        if b.role or b.member
    ]
    access_context = (
        {
            k: getattr(f.access, k)
            for k in ("principal_email", "caller_ip", "service_name", "method_name")
            if getattr(f.access, k, "")
        }
        if f.access
        else {}
    )
    network_context = [
        f"{c.source_ip or '*'} -> {c.destination_ip}:{c.destination_port} ({_enum_name(c.protocol)})"
        for c in f.connections[:3]
        if c.destination_ip or c.destination_port or c.source_ip
    ]
    source_props = dict(
        islice(
            (
                (k, str(v).strip()[:200])
                for k, v in (f.source_properties or {}).items()
                if k not in _SKIP_PROPS and v and str(v).strip()
            ),
            6,
        )
    )

    record = {
        "category": f.category or "UNKNOWN",
        "finding_class": _enum_name(f.finding_class, _FINDING_CLASS_FALLBACK),
        "severity": severity,
        "attack_exposure_score": exposure_score,
        "resource_display_name": res_display,
        "matches_target_vm": bool(
            instance_name
            and (
                instance_name.lower() in f.resource_name.lower()
                or instance_name.lower() == res_display.lower()
            )
        ),
        "description": (f.description or "")[:600],
        "next_steps": (f.next_steps or "")[:600],
    }
    if exposed_resources:
        record["exposed_resources_count"] = exposed_resources
    if iam_context:
        record["iam_bindings"] = iam_context
    if access_context:
        record["access_activity"] = access_context
    if network_context:
        record["network_connections"] = network_context
    if source_props:
        record["technical_properties"] = source_props
    return record


def _list_scc_results_sync(parent_base: str, max_fetch: int = 250) -> list:
    """Query SCC v2 across all sources in the global location."""
    req = securitycenter_v2.ListFindingsRequest(
        parent=f"{parent_base}/sources/-/locations/global",
        filter=_SCC_FILTER,
        page_size=min(max_fetch, 100),
    )
    return list(islice(get_scc_v2_client().list_findings(request=req), max_fetch))


async def get_scc_findings(
    project_id: str = "",
    org_id: str = "",
    instance_name: str = "",
) -> str:
    """Retrieves active Google Cloud Security Command Center (SCC) posture, threat, and attack path findings.

    Excludes raw software/OS CVE findings (handled by OS Config) and groups findings by criticality
    (CRITICAL, HIGH, MEDIUM, LOW) with full attack exposure, IAM, network, and remediation context.

    Args:
        project_id: GCP project ID (used when org_id is not specified).
        org_id: Optional GCP organization ID (e.g. '123456789012') for organization-level SCC queries.
        instance_name: Optional Compute Engine VM name to highlight findings affecting a specific VM.
    """
    project_id = project_id.strip()
    instance_name = instance_name.strip()
    org_id = org_id.strip().removeprefix("organizations/")

    if org_id:
        if not org_id.isdigit():
            return json.dumps({"error": f"Invalid organization ID: {org_id}"})
        parent_base = f"organizations/{org_id}"
    elif project_id:
        parent_base = f"projects/{project_id}"
    else:
        return json.dumps({"error": "Missing required project_id or org_id parameter."})

    try:
        raw_results = await asyncio.to_thread(_list_scc_results_sync, parent_base)
        records = [_extract_finding_record(r, instance_name) for r in raw_results]
    except Exception as exc:
        return json.dumps({
            "scope": parent_base,
            "error": f"Failed to query Security Command Center findings: {str(exc)}",
            "total_active_findings": 0,
        }, indent=2)
    severity_counts = Counter(r["severity"] for r in records)
    max_exposure = max((r["attack_exposure_score"] for r in records), default=0.0)

    records.sort(
        key=lambda r: (
            _SEVERITY_RANK.get(r["severity"], 0),
            r["attack_exposure_score"],
            _CLASS_RANK.get(r["finding_class"], 0),
            r["matches_target_vm"],
        ),
        reverse=True,
    )

    findings_by_severity = {"CRITICAL": [], "HIGH": [], "MEDIUM": [], "LOW": []}
    per_cat_seen = Counter()

    for rec in records:
        sev = rec["severity"]
        if per_cat_seen[(sev, rec["category"])] >= 6:
            continue
        per_cat_seen[(sev, rec["category"])] += 1
        if len(findings_by_severity[sev]) < 15:
            findings_by_severity[sev].append(rec)

    return json.dumps({
        "scope": parent_base,
        "target_vm_filter": instance_name or None,
        "total_active_findings": len(records),
        "max_attack_exposure_score": max_exposure,
        "severity_breakdown": {k: severity_counts.get(k, 0) for k in _SEVERITY_RANK},
        "findings_by_severity": findings_by_severity,
    }, indent=2)
