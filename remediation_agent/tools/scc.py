"""Security Command Center (SCC) findings discovery, context enrichment, and criticality triage tool."""

import asyncio
from collections import Counter
from itertools import islice
import json
import proto
from google.cloud import securitycenter_v2
from . import get_scc_v2_client


_SEVERITY_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
_CLASS_RANK = {
    "TOXIC_COMBINATION": 5,
    "CHOKEPOINT": 4,
    "THREAT": 3,
    "EXTERNAL_EXPOSURE": 3,
    "EXTENSIVE_EXPOSURE": 3,
    "VULNERABILITY": 2,
    "MISCONFIGURATION": 2,
    "POSTURE_VIOLATION": 2,
    "SCC_ERROR": 1,
}
_FINDING_CLASS_FALLBACK = {10: "EXTERNAL_EXPOSURE"}
_SKIP_PROPS = {"security_marks", "compliance_standards", "scanner_name", "ResourcePath", "ProjectId"}
_SCC_POSTURE_FILTER = 'state="ACTIVE" AND NOT mute="MUTED" AND NOT finding_class="VULNERABILITY"'


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
        "name": f.name,
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
    if exp and exp.attack_exposure_result:
        record["attack_exposure_result"] = exp.attack_exposure_result
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

    vuln = getattr(f, "vulnerability", None)
    cve = getattr(vuln, "cve", None) if vuln else None
    off_pkg = getattr(vuln, "offending_package", None) if vuln else None
    fix_pkg = getattr(vuln, "fixed_package", None) if vuln else None
    if vuln and ((cve and getattr(cve, "id", "")) or (off_pkg and getattr(off_pkg, "package_name", ""))):
        cvss_obj = getattr(cve, "cvssv3", None) if cve else None
        exploit_act = _enum_name(getattr(cve, "exploitation_activity", None)) if cve else ""
        vuln_info: dict = {
            "cve": getattr(cve, "id", "") or "UNKNOWN",
            "cvss_v3": round(float(getattr(cvss_obj, "base_score", 0.0) or 0.0), 1),
            "upstream_fix_available": bool(getattr(cve, "upstream_fix_available", False)),
            "observed_in_the_wild": bool(getattr(cve, "observed_in_the_wild", False)),
            "zero_day": bool(getattr(cve, "zero_day", False)),
            "reachable": bool(getattr(vuln, "reachable", False)),
        }
        if exploit_act and "UNSPECIFIED" not in exploit_act:
            vuln_info["exploitation_activity"] = exploit_act
        if off_pkg and getattr(off_pkg, "package_name", ""):
            ver = getattr(off_pkg, "package_version", "")
            vuln_info["offending_package"] = f"{off_pkg.package_name} ({ver})" if ver else off_pkg.package_name
        if fix_pkg and getattr(fix_pkg, "package_name", ""):
            ver = getattr(fix_pkg, "package_version", "")
            vuln_info["fixed_package"] = f"{fix_pkg.package_name} ({ver})" if ver else fix_pkg.package_name
        record["vulnerability"] = vuln_info

    return record


def _list_scc_results_sync(
    parent_base: str,
    include_vulnerabilities: bool = False,
    vuln_severities: set[str] | None = None,
    max_fetch: int = 250,
) -> list:
    """Query SCC v2 across all sources in the global location."""
    if include_vulnerabilities:
        sevs = sorted(vuln_severities) if vuln_severities else ["CRITICAL", "HIGH"]
        sev_clause = " OR ".join(f'severity="{s}"' for s in sevs)
        scc_filter = f'state="ACTIVE" AND NOT mute="MUTED" AND (NOT finding_class="VULNERABILITY" OR {sev_clause})'
    else:
        scc_filter = _SCC_POSTURE_FILTER
    req = securitycenter_v2.ListFindingsRequest(
        parent=f"{parent_base}/sources/-/locations/global",
        filter=scc_filter,
        page_size=min(max_fetch, 100),
    )
    return list(islice(get_scc_v2_client().list_findings(request=req), max_fetch))


async def get_scc_findings(
    project_id: str = "",
    org_id: str = "",
    instance_name: str = "",
    severities: list[str] | None = None,
    include_vulnerabilities: bool = False,
) -> str:
    """Retrieves active Google Cloud Security Command Center (SCC) posture, threat, attack path, and optional vulnerability findings.

    Always returns overall severity_breakdown counts across the scope, while optionally filtering
    the returned findings_by_severity details to the requested severities (e.g. ['HIGH'], ['MEDIUM', 'HIGH'], ['CRITICAL']).

    Args:
        project_id: GCP project ID (used when org_id is not specified).
        org_id: Optional GCP organization ID (e.g. '123456789012') for organization-level SCC queries.
        instance_name: Optional Compute Engine VM name to highlight findings affecting a specific VM.
        severities: Optional list of severity levels to return ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW'). Leave empty for all.
        include_vulnerabilities: Set True on risk/vulnerability or org-wide scans to include SCC CVE findings with exploitability intelligence (observed_in_the_wild, zero_day, exploitation_activity). Defaults to False.
    """
    project_id = project_id.strip()
    instance_name = instance_name.strip()
    org_id = org_id.strip().removeprefix("organizations/")
    wanted = {s.strip().upper() for s in (severities or []) if s and s.strip()} & set(_SEVERITY_RANK)

    if org_id:
        if not org_id.isdigit():
            return json.dumps({"error": f"Invalid organization ID: {org_id}"})
        parent_base = f"organizations/{org_id}"
    elif project_id:
        parent_base = f"projects/{project_id}"
    else:
        return json.dumps({"error": "Missing required project_id or org_id parameter."})

    try:
        raw_results = await asyncio.to_thread(
            _list_scc_results_sync, parent_base, bool(include_vulnerabilities), wanted or None
        )
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
            bool((r.get("vulnerability") or {}).get("observed_in_the_wild") or (r.get("vulnerability") or {}).get("zero_day")),
            r["attack_exposure_score"],
            _CLASS_RANK.get(r["finding_class"], 0),
            r["matches_target_vm"],
        ),
        reverse=True,
    )

    findings_by_severity = {
        k: [] for k in _SEVERITY_RANK if not wanted or k in wanted
    }
    per_cat_seen = Counter()

    for rec in records:
        sev = rec["severity"]
        if sev not in findings_by_severity:
            continue
        if per_cat_seen[(sev, rec["category"])] >= 6:
            continue
        per_cat_seen[(sev, rec["category"])] += 1
        if len(findings_by_severity[sev]) < 15:
            findings_by_severity[sev].append(rec)

    return json.dumps({
        "scope": parent_base,
        "target_vm_filter": instance_name or None,
        "severities_filter": sorted(wanted) if wanted else None,
        "total_active_findings": len(records),
        "max_attack_exposure_score": max_exposure,
        "severity_breakdown": {k: severity_counts.get(k, 0) for k in _SEVERITY_RANK},
        "findings_by_severity": findings_by_severity,
    }, indent=2)


async def get_scc_attack_paths(org_id: str = "", attack_exposure_result: str = "") -> str:
    """Retrieves Security Command Center (SCC) v2 attack path graphs showing hop-by-hop nodes and target crown-jewel resources.

    Args:
        org_id: Optional GCP organization ID (e.g. '123456789012') to query the latest simulation.
        attack_exposure_result: Optional attack_exposure_result resource name from an SCC finding.
    """
    parent = attack_exposure_result.strip().replace("/locations/global/", "/")
    if not parent:
        clean_org = org_id.strip().removeprefix("organizations/")
        if not clean_org.isdigit():
            return json.dumps({"error": "Provide a valid org_id or attack_exposure_result path."})
        parent = f"organizations/{clean_org}/simulations/latest"

    req = securitycenter_v2.ListAttackPathsRequest(parent=parent, page_size=15)
    try:
        paths = await asyncio.to_thread(lambda: list(islice(get_scc_v2_client().list_attack_paths(request=req), 15)))
    except Exception as exc:
        return json.dumps({"parent": parent, "error": f"Failed to list SCC attack paths: {exc}"}, indent=2)

    records = [
        {
            "name": p.name,
            "nodes": [
                {
                    "uuid": n.uuid,
                    "display_name": n.display_name or (n.resource or "").split("/")[-1],
                    "resource_type": n.resource_type,
                    "resource": n.resource,
                }
                for n in p.path_nodes
            ],
            "edges": [{"source": e.source, "destination": e.destination} for e in p.edges],
        }
        for p in paths
    ]
    return json.dumps({"parent": parent, "attack_paths_count": len(records), "attack_paths": records}, indent=2)


async def set_scc_finding_mute(finding_name: str, mute: str = "MUTED") -> str:
    """Updates the mute state (MUTED or UNMUTED) of a Security Command Center v2 finding.

    Requires explicit operator confirmation before execution.

    Args:
        finding_name: Full SCC v2 finding resource name (from get_scc_findings 'name' field).
        mute: Target mute state: 'MUTED' (default) or 'UNMUTED'.
    """
    mute_enum = getattr(
        securitycenter_v2.Finding.Mute,
        mute.strip().upper(),
        securitycenter_v2.Finding.Mute.MUTED,
    )
    req = securitycenter_v2.SetMuteRequest(name=finding_name.strip(), mute=mute_enum)
    try:
        finding = await asyncio.to_thread(get_scc_v2_client().set_mute, request=req)
        return proto.Message.to_json(finding, use_integers_for_enums=False)
    except Exception as exc:
        return json.dumps({"error": f"Failed to update mute state on '{finding_name}': {exc}"}, indent=2)

