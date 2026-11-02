"""Compute Engine boot disk recovery snapshot and rollback tools."""

import asyncio
from datetime import datetime, timezone
import json
from google.cloud import compute_v1
from . import get_boot_disk_info, get_disks_client, get_instances_client, get_snapshots_client


async def list_disk_snapshots(project_id: str, instance_name: str = "") -> str:
    """Lists Compute Engine disk snapshots in a project, sorted newest first.

    Args:
        project_id: GCP project ID.
        instance_name: Optional VM instance or boot disk name filter.
    """
    client = get_snapshots_client()
    needle = instance_name.strip().lower()
    try:
        snaps = await asyncio.to_thread(lambda: list(client.list(project=project_id)))
    except Exception as exc:
        return json.dumps({"error": f"Failed to list disk snapshots: {exc}"}, indent=2)

    records = [
        {
            "name": s.name,
            "status": s.status,
            "source_disk": (s.source_disk or "").split("/")[-1],
            "disk_size_gb": s.disk_size_gb,
            "creation_timestamp": s.creation_timestamp,
            "description": s.description,
        }
        for s in snaps
        if not needle or needle in (s.name or "").lower() or needle in (s.source_disk or "").lower()
    ]
    records.sort(key=lambda r: r["creation_timestamp"] or "", reverse=True)
    return json.dumps({"project_id": project_id, "snapshots": records[:25]}, indent=2)



async def create_boot_disk_snapshot(project_id: str, zone: str, instance_name: str) -> str:
    """Creates a point-in-time recovery snapshot of the VM's boot disk before patching.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name.
    """
    instances_client = get_instances_client()
    disks_client = get_disks_client()

    try:
        instance = await asyncio.to_thread(
            instances_client.get, project=project_id, zone=zone, instance=instance_name
        )
        boot_disk_name, _ = get_boot_disk_info(instance)
        if not boot_disk_name:
            return json.dumps({"status": "FAILED", "error": f"No boot disk found on {instance_name}."})

        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
        snapshot_name = f"prepatch-{instance_name}-{timestamp}"
        start_ts = datetime.now(timezone.utc)

        operation = await asyncio.to_thread(
            disks_client.create_snapshot,
            project=project_id,
            zone=zone,
            disk=boot_disk_name,
            snapshot_resource=compute_v1.Snapshot(
                name=snapshot_name,
                description=f"Pre-patch snapshot for {instance_name} created by PatchAdvisor.",
            ),
        )
        await asyncio.to_thread(operation.result, timeout=300)
        elapsed = max(1, int((datetime.now(timezone.utc) - start_ts).total_seconds()))

        if operation.error_code:
            return json.dumps({
                "status": "FAILED",
                "snapshot_name": snapshot_name,
                "error": f"{operation.error_code}: {operation.error_message}",
            }, indent=2)

        return json.dumps({
            "status": "SUCCESS",
            "snapshot_name": snapshot_name,
            "boot_disk": boot_disk_name,
            "elapsed_seconds": elapsed,
        }, indent=2)
    except Exception as exc:
        return json.dumps({"status": "FAILED", "error": str(exc)}, indent=2)


async def rollback_vm_to_snapshot(
    project_id: str,
    zone: str,
    instance_name: str,
    snapshot_name: str,
    reason: str = "",
) -> str:
    """Restores a VM's boot disk from a pre-patch snapshot and restarts the instance.

    Args:
        project_id: GCP project ID.
        zone: Compute Engine zone (e.g. us-central1-c).
        instance_name: VM instance name to roll back.
        snapshot_name: Pre-patch snapshot name to restore from.
        reason: Reason for triggering the rollback.
    """
    instances_client = get_instances_client()
    disks_client = get_disks_client()
    restored_disk_name = f"{instance_name}-restored-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"

    try:
        instance = await asyncio.to_thread(
            instances_client.get, project=project_id, zone=zone, instance=instance_name
        )
        _, old_boot_device = get_boot_disk_info(instance)
        if not old_boot_device:
            return json.dumps({"status": "FAILED", "error": f"No boot disk device found on {instance_name}."})

        disk_op = await asyncio.to_thread(
            disks_client.insert,
            project=project_id,
            zone=zone,
            disk_resource=compute_v1.Disk(
                name=restored_disk_name,
                source_snapshot=f"projects/{project_id}/global/snapshots/{snapshot_name}",
            ),
        )
        await asyncio.to_thread(disk_op.result, timeout=180)
        if getattr(disk_op, "error_code", None):
            return json.dumps({
                "status": "FAILED",
                "instance_name": instance_name,
                "snapshot_name": snapshot_name,
                "error": f"{disk_op.error_code}: {disk_op.error_message}",
            }, indent=2)

        stop_op = await asyncio.to_thread(
            instances_client.stop, project=project_id, zone=zone, instance=instance_name
        )
        await asyncio.to_thread(stop_op.result, timeout=180)

        detach_op = await asyncio.to_thread(
            instances_client.detach_disk,
            project=project_id,
            zone=zone,
            instance=instance_name,
            device_name=old_boot_device,
        )
        await asyncio.to_thread(detach_op.result, timeout=120)

        attach_op = await asyncio.to_thread(
            instances_client.attach_disk,
            project=project_id,
            zone=zone,
            instance=instance_name,
            attached_disk_resource=compute_v1.AttachedDisk(
                boot=True,
                auto_delete=True,
                source=f"projects/{project_id}/zones/{zone}/disks/{restored_disk_name}",
            ),
        )
        await asyncio.to_thread(attach_op.result, timeout=120)

        start_op = await asyncio.to_thread(
            instances_client.start, project=project_id, zone=zone, instance=instance_name
        )
        await asyncio.to_thread(start_op.result, timeout=180)

        return json.dumps({
            "status": "ROLLED_BACK",
            "instance_name": instance_name,
            "snapshot_name": snapshot_name,
            "restored_disk": restored_disk_name,
            "reason": reason,
        }, indent=2)
    except Exception as exc:
        return json.dumps({
            "status": "FAILED",
            "instance_name": instance_name,
            "snapshot_name": snapshot_name,
            "error": str(exc),
        }, indent=2)
