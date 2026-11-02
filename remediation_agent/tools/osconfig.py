"""OS Config and Compute Engine VM discovery, metadata hardening, and patching tools."""

import asyncio
from collections import defaultdict
import json
import proto
from google.cloud import compute_v1, osconfig_v1
from . import get_instances_client, get_osconfig_client, get_osconfig_zonal_client

_TERMINAL_PATCH_STATES = {
    osconfig_v1.PatchJob.State.SUCCEEDED,
    osconfig_v1.PatchJob.State.COMPLETED_WITH_ERRORS,
    osconfig_v1.PatchJob.State.CANCELED,
    osconfig_v1.PatchJob.State.TIMED_OUT,
}


def _cvss_severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    return "MEDIUM" if score >= 4.0 else "LOW"


async def list_project_vms(project_id: str, zone: str = "") -> str:
    """Lists Compute Engine VMs in a project or zone with their raw status, machine type, labels, and tags.

    Args:
        project_id: GCP project ID.
        zone: Optional Compute Engine zone filter (e.g. us-central1-c). Leave empty to scan all zones.
    """
    client = get_instances_client()
    try:
        if zone:
            inst_iter = await asyncio.to_thread(lambda: list(client.list(project=project_id, zone=zone)))
            raw_pairs = [(zone, inst) for inst in inst_iter]
        else:
            agg = await asyncio.to_thread(lambda: list(client.aggregated_list(project=project_id)))
            raw_pairs = [
                (scope_name.split("/")[-1], inst)
                for scope_name, scoped_list in agg
                if scoped_list.instances
                for inst in scoped_list.instances
            ]
    except Exception as exc:
        return json.dumps({"error": f"Failed to list project VMs: {exc}"})

    vms = [
        {
            "name": inst.name,
            "zone": inst_zone,
            "status": inst.status,
            "machine_type": inst.machine_type.split("/")[-1],
            "labels": dict(inst.labels),
            "tags": list(inst.tags.items),
        }
        for inst_zone, inst in raw_pairs
    ]
    return json.dumps({"project_id": project_id, "instances": vms}, indent=2)


async def get_vm_instance(project_id: str, zone: str, instance_name: str) -> str:
    """Retrieves full Compute Engine VM instance metadata from the GCE API.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
    """
    client = get_instances_client()
    try:
        instance = await asyncio.to_thread(client.get, project=project_id, zone=zone, instance=instance_name)
        return proto.Message.to_json(instance, use_integers_for_enums=False)
    except Exception as exc:
        return json.dumps({"error": f"Failed to retrieve instance: {exc}"})


async def set_vm_metadata(
    project_id: str,
    zone: str,
    instance_name: str,
    metadata_updates: dict[str, str],
) -> str:
    """Updates Compute Engine VM instance metadata keys (such as enable-oslogin or serial-port-enable) while preserving existing keys.

    Requires explicit operator confirmation before execution.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
        metadata_updates: Dictionary of metadata key-value pairs to set on the instance.
    """
    if not metadata_updates:
        return json.dumps({"error": "No metadata_updates provided."})

    client = get_instances_client()
    try:
        instance = await asyncio.to_thread(client.get, project=project_id, zone=zone, instance=instance_name)
        merged = {item.key: item.value for item in (instance.metadata.items or []) if item.key}
        clean_updates = {k.strip(): str(v) for k, v in metadata_updates.items() if k and k.strip()}
        merged.update(clean_updates)

        metadata_resource = compute_v1.Metadata(
            fingerprint=instance.metadata.fingerprint,
            items=[compute_v1.Items(key=k, value=v) for k, v in merged.items()],
        )
        operation = await asyncio.to_thread(
            client.set_metadata,
            project=project_id,
            zone=zone,
            instance=instance_name,
            metadata_resource=metadata_resource,
        )
        await asyncio.to_thread(operation.result, timeout=120)
        if getattr(operation, "error_code", None):
            return json.dumps({
                "status": "FAILED",
                "instance_name": instance_name,
                "error": f"{operation.error_code}: {operation.error_message}",
            }, indent=2)
        return json.dumps({
            "status": "SUCCESS",
            "instance_name": instance_name,
            "zone": zone,
            "updated_metadata": clean_updates,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"status": "FAILED", "instance_name": instance_name, "error": str(exc)}, indent=2)


async def get_vulnerability_report(
    project_id: str,
    zone: str,
    instance_name: str,
    severities: list[str] | None = None,
) -> str:
    """Retrieves the OS Config VulnerabilityReport for a Compute Engine VM.

    Always returns overall CVE and package summary counts across the VM, while optionally filtering
    packages to those containing at least one CVE in the requested severities.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
        severities: Optional list of severity levels to match (e.g. ['HIGH'], ['MEDIUM', 'HIGH'], ['CRITICAL']). Leave empty for all.
    """
    client = get_osconfig_zonal_client()
    name = client.vulnerability_report_path(project_id, zone, instance_name)
    try:
        report = await asyncio.to_thread(client.get_vulnerability_report, name=name)
    except Exception as exc:
        return json.dumps({"instance": instance_name, "error": str(exc), "total_cves": 0})

    wanted = {s.strip().upper() for s in (severities or []) if s and s.strip()} & {"CRITICAL", "HIGH", "MEDIUM", "LOW"}
    pkg_map = defaultdict(lambda: {
        "cves": {},
        "patchable_cves": {},
        "unfixed_upstream_cves": {},
        "installed_version": "",
        "available_version": "",
    })
    patchable_cve_count = 0
    unfixed_upstream_cve_count = 0
    cve_severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    for item in report.vulnerabilities:
        details = item.details
        cve_id = details.cve if details else "UNKNOWN"
        cvss = round(details.cvss_v3.base_score, 1) if (details and details.cvss_v3) else 0.0
        cve_severity_counts[_cvss_severity(cvss)] += 1
        has_fix = bool(item.available_inventory_item_ids)
        if has_fix:
            patchable_cve_count += 1
        else:
            unfixed_upstream_cve_count += 1

        avail_ver = ""
        if item.available_inventory_item_ids:
            parts = item.available_inventory_item_ids[0].split(":")
            if len(parts) >= 3:
                avail_ver = ":".join(parts[2:])

        for raw_pkg in item.installed_inventory_item_ids:
            parts = raw_pkg.removeprefix("installedPackage-").split(":")
            entry = pkg_map[parts[0]]
            entry["cves"][cve_id] = max(entry["cves"].get(cve_id, 0.0), cvss)
            if len(parts) >= 3 and not entry["installed_version"]:
                entry["installed_version"] = ":".join(parts[2:])
            if avail_ver:
                entry["available_version"] = avail_ver
            target_bucket = entry["patchable_cves"] if has_fix else entry["unfixed_upstream_cves"]
            target_bucket[cve_id] = max(target_bucket.get(cve_id, 0.0), cvss)

    def _filter_cves(cve_scores: dict[str, float]) -> dict[str, float]:
        if not wanted:
            return cve_scores
        return {cid: sc for cid, sc in cve_scores.items() if _cvss_severity(sc) in wanted}

    def _top_cves(cve_scores: dict[str, float]) -> list[str]:
        return [cid for cid, _ in sorted(cve_scores.items(), key=lambda kv: (kv[1], kv[0]), reverse=True)[:5]]

    total_patchable_pkgs = sum(1 for d in pkg_map.values() if d["patchable_cves"])
    total_unfixed_pkgs = len(pkg_map) - total_patchable_pkgs

    ranked_packages = []
    for pkg_name, data in pkg_map.items():
        m_cves = _filter_cves(data["cves"])
        if not m_cves:
            continue
        m_patch = _filter_cves(data["patchable_cves"])
        m_unfix = _filter_cves(data["unfixed_upstream_cves"])
        max_sc = max(m_cves.values(), default=0.0)
        has_repo_fix = bool(m_patch) if wanted else bool(data["patchable_cves"])
        ranked_packages.append({
            "package": pkg_name,
            "installed_version": data["installed_version"],
            "available_version": data["available_version"],
            "fix_available_in_repo": has_repo_fix,
            "severity": _cvss_severity(max_sc),
            "max_cvss": max_sc,
            "cve_count": len(m_cves),
            "patchable_cve_count": len(m_patch),
            "unfixed_upstream_cve_count": len(m_unfix),
            "cves": _top_cves(m_patch or m_cves),
        })

    ranked_packages.sort(
        key=lambda p: (p["fix_available_in_repo"], p["max_cvss"], p["cve_count"]),
        reverse=True,
    )
    filtered_patchable = [p for p in ranked_packages if p["fix_available_in_repo"]]
    filtered_unfixed = [p for p in ranked_packages if not p["fix_available_in_repo"]]

    return json.dumps({
        "instance": instance_name,
        "zone": zone,
        "report_update_time": str(report.update_time or ""),
        "severities_filter": sorted(wanted) if wanted else None,
        "total_cves": len(report.vulnerabilities),
        "cve_severity_breakdown": cve_severity_counts,
        "patchable_cves_count": patchable_cve_count,
        "unfixed_upstream_cves_count": unfixed_upstream_cve_count,
        "patchable_packages_count": total_patchable_pkgs,
        "unfixed_upstream_packages_count": total_unfixed_pkgs,
        "patchable_packages": filtered_patchable[:40],
        "unfixed_upstream_packages": filtered_unfixed[:15],
    }, indent=2)


async def get_guest_inventory(project_id: str, zone: str, instance_name: str) -> str:
    """Retrieves OS Config guest package inventory and available OS package updates for a VM.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
    """
    client = get_osconfig_zonal_client()
    name = client.inventory_path(project_id, zone, instance_name)
    try:
        inv = await asyncio.to_thread(
            client.get_inventory,
            request=osconfig_v1.GetInventoryRequest(name=name, view=osconfig_v1.InventoryView.FULL),
        )
    except Exception as exc:
        return json.dumps({"instance": instance_name, "error": str(exc)})

    installed, available = {}, {}
    for item in inv.items.values():
        for target_dict, container in ((installed, item.installed_package), (available, item.available_package)):
            if container:
                pkg = container.apt_package or container.yum_package or container.zypper_package or container.cos_package
                if pkg and pkg.package_name:
                    target_dict[pkg.package_name] = pkg.version

    return json.dumps({
        "instance": instance_name,
        "zone": zone,
        "update_time": str(inv.update_time or ""),
        "os_info": proto.Message.to_dict(inv.os_info, use_integers_for_enums=False) if inv.os_info else {},
        "available_package_updates": available,
        "installed_packages_count": len(installed),
        "installed_packages": installed,
    }, indent=2)


async def apply_osconfig_patch(
    project_id: str,
    zone: str,
    instance_name: str,
    packages: list[str],
    reboot_policy: str = "NEVER",
) -> str:
    """Applies targeted package updates to a Compute Engine VM using Google Cloud OS Config Patch Jobs.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
        packages: List of package names to upgrade.
        reboot_policy: Reboot strategy: NEVER (default), REBOOT_IF_NEEDED, or ALWAYS.
    """
    package_list = [p.strip() for p in packages if p.strip()]
    if not package_list:
        return json.dumps({"error": "No packages specified for upgrade."})

    reboot_config = getattr(
        osconfig_v1.PatchConfig.RebootConfig,
        reboot_policy.strip().upper(),
        osconfig_v1.PatchConfig.RebootConfig.NEVER,
    )
    request = osconfig_v1.ExecutePatchJobRequest(
        parent=f"projects/{project_id}",
        description=f"PatchAdvisor remediation on {instance_name}: {', '.join(package_list)}",
        instance_filter=osconfig_v1.PatchInstanceFilter(instances=[f"zones/{zone}/instances/{instance_name}"]),
        patch_config=osconfig_v1.PatchConfig(
            reboot_config=reboot_config,
            apt=osconfig_v1.AptSettings(exclusive_packages=package_list),
            yum=osconfig_v1.YumSettings(exclusive_packages=package_list),
        ),
    )

    client = get_osconfig_client()
    try:
        job = await asyncio.to_thread(client.execute_patch_job, request=request)
        for _ in range(60):
            if job.state in _TERMINAL_PATCH_STATES:
                break
            await asyncio.sleep(5)
            job = await asyncio.to_thread(client.get_patch_job, name=job.name)
        return proto.Message.to_json(job, use_integers_for_enums=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)
