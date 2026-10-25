"""VM package patching tool executed via Google Cloud OS Config Patch Jobs."""

import asyncio
import json
import proto
from google.cloud import osconfig_v1
from . import get_osconfig_client

_TERMINAL_STATES = {
    osconfig_v1.PatchJob.State.SUCCEEDED,
    osconfig_v1.PatchJob.State.COMPLETED_WITH_ERRORS,
    osconfig_v1.PatchJob.State.CANCELED,
    osconfig_v1.PatchJob.State.TIMED_OUT,
}


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
            if job.state in _TERMINAL_STATES:
                break
            await asyncio.sleep(5)
            job = await asyncio.to_thread(client.get_patch_job, name=job.name)
        return proto.Message.to_json(job, use_integers_for_enums=False)
    except Exception as exc:
        return json.dumps({"error": str(exc)}, indent=2)
