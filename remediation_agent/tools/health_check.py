"""VM runtime health and OS Config patch job verification tools."""

import asyncio
from datetime import datetime, timedelta, timezone
from itertools import islice
import json
import proto
from google.cloud import logging_v2
from . import get_instances_client, get_logging_client, get_osconfig_client


async def check_vm_runtime_health(project_id: str, zone: str, instance_name: str) -> str:
    """Retrieves the VM instance state, network interfaces, and raw serial port console tail.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
    """
    client = get_instances_client()
    try:
        instance = await asyncio.to_thread(client.get, project=project_id, zone=zone, instance=instance_name)
    except Exception as exc:
        return json.dumps({"error": f"Failed to retrieve instance state: {exc}"}, indent=2)

    serial_tail = ""
    try:
        serial = await asyncio.to_thread(
            client.get_serial_port_output, project=project_id, zone=zone, instance=instance_name
        )
        serial_tail = (serial.contents or "")[-4000:]
    except Exception:
        pass

    return json.dumps({
        "instance_name": instance.name,
        "status": instance.status,
        "network_interfaces": [proto.Message.to_dict(nic, use_integers_for_enums=False) for nic in instance.network_interfaces],
        "serial_port_tail": serial_tail,
    }, indent=2)


async def verify_patch_compliance(project_id: str, patch_job_id: str) -> str:
    """Retrieves an OS Config PatchJob and its per-instance execution details.

    Args:
        project_id: GCP project ID.
        patch_job_id: OS Config patch job ID or full resource name.
    """
    client = get_osconfig_client()
    job_name = patch_job_id if "/" in patch_job_id else f"projects/{project_id}/patchJobs/{patch_job_id}"
    try:
        job = await asyncio.to_thread(client.get_patch_job, name=job_name)
        details = await asyncio.to_thread(lambda: list(client.list_patch_job_instance_details(parent=job_name)))
    except Exception as exc:
        return json.dumps({"error": f"Failed to retrieve patch job '{job_name}': {exc}"}, indent=2)

    return json.dumps({
        "patch_job": proto.Message.to_dict(job, use_integers_for_enums=False),
        "instance_details": [proto.Message.to_dict(d, use_integers_for_enums=False) for d in details],
    }, indent=2)


async def get_vm_system_logs(
    project_id: str,
    zone: str,
    instance_name: str,
    minutes: int = 30,
) -> str:
    """Retrieves recent Cloud Logging entries (syslog, systemd, OSConfigAgent) for a Compute Engine VM.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
        minutes: Lookback window in minutes (default 30).
    """
    cutoff = (datetime.now(timezone.utc) - timedelta(minutes=max(1, min(minutes, 1440)))).strftime("%Y-%m-%dT%H:%M:%SZ")
    safe_inst = instance_name.strip().replace('"', "")
    safe_zone = zone.strip().replace('"', "")
    log_filter = (
        f'resource.type="gce_instance" AND timestamp>="{cutoff}" '
        f'AND (labels."compute.googleapis.com/resource_name"="{safe_inst}" OR "{safe_inst}")'
    )
    if safe_zone:
        log_filter += f' AND resource.labels.zone="{safe_zone}"'

    client = get_logging_client()
    req = logging_v2.types.ListLogEntriesRequest(
        resource_names=[f"projects/{project_id}"],
        filter=log_filter,
        order_by="timestamp desc",
        page_size=40,
    )
    try:
        entries = await asyncio.to_thread(lambda: list(islice(client.list_log_entries(request=req), 40)))
    except Exception as exc:
        return json.dumps({"instance": instance_name, "error": f"Failed to query Cloud Logging: {exc}"}, indent=2)

    records = []
    for e in entries:
        msg = e.text_payload or (dict(e.json_payload) if e.json_payload else "")
        records.append({
            "timestamp": str(e.timestamp or ""),
            "severity": getattr(e.severity, "name", str(e.severity or "DEFAULT")),
            "log_name": (e.log_name or "").split("/")[-1],
            "message": str(msg)[:400],
        })
    return json.dumps({"instance": instance_name, "zone": zone, "entries_count": len(records), "entries": records}, indent=2)

