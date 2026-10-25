"""OS Config and Compute Engine discovery tools."""

import asyncio
from collections import defaultdict
import json
import proto
from google.cloud import osconfig_v1
from . import get_instances_client, get_osconfig_zonal_client


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


async def get_vulnerability_report(project_id: str, zone: str, instance_name: str) -> str:
    """Retrieves the OS Config VulnerabilityReport for a Compute Engine VM.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
    """
    client = get_osconfig_zonal_client()
    name = client.vulnerability_report_path(project_id, zone, instance_name)
    try:
        report = await asyncio.to_thread(client.get_vulnerability_report, name=name)
    except Exception as exc:
        return json.dumps({"instance": instance_name, "error": str(exc), "total_cves": 0})

    pkg_map = defaultdict(lambda: {
        "cves": set(),
        "patchable_cves": set(),
        "unfixed_upstream_cves": set(),
        "max_cvss": 0.0,
        "installed_version": "",
        "available_version": "",
    })
    patchable_cve_count = 0
    unfixed_upstream_cve_count = 0

    for item in report.vulnerabilities:
        details = item.details
        cve_id = details.cve if details else "UNKNOWN"
        cvss = round(details.cvss_v3.base_score, 1) if (details and details.cvss_v3) else 0.0
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
            entry["cves"].add(cve_id)
            if len(parts) >= 3 and not entry["installed_version"]:
                entry["installed_version"] = ":".join(parts[2:])
            if avail_ver:
                entry["available_version"] = avail_ver
            (entry["patchable_cves"] if has_fix else entry["unfixed_upstream_cves"]).add(cve_id)
            if cvss > entry["max_cvss"]:
                entry["max_cvss"] = cvss

    ranked_packages = [
        {
            "package": pkg_name,
            "installed_version": data["installed_version"],
            "available_version": data["available_version"],
            "fix_available_in_repo": bool(data["patchable_cves"]),
            "max_cvss": data["max_cvss"],
            "cve_count": len(data["cves"]),
            "patchable_cve_count": len(data["patchable_cves"]),
            "unfixed_upstream_cve_count": len(data["unfixed_upstream_cves"]),
            "cves": sorted(data["patchable_cves"] or data["cves"])[:5],
        }
        for pkg_name, data in sorted(
            pkg_map.items(),
            key=lambda x: (bool(x[1]["patchable_cves"]), x[1]["max_cvss"], len(x[1]["cves"])),
            reverse=True,
        )
    ]

    patchable_packages = [p for p in ranked_packages if p["fix_available_in_repo"]]
    unfixed_packages = [p for p in ranked_packages if not p["fix_available_in_repo"]]

    return json.dumps({
        "instance": instance_name,
        "zone": zone,
        "report_update_time": str(report.update_time or ""),
        "total_cves": len(report.vulnerabilities),
        "patchable_cves_count": patchable_cve_count,
        "unfixed_upstream_cves_count": unfixed_upstream_cve_count,
        "patchable_packages_count": len(patchable_packages),
        "unfixed_upstream_packages_count": len(unfixed_packages),
        "patchable_packages": patchable_packages[:40],
        "unfixed_upstream_packages": unfixed_packages[:10],
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
