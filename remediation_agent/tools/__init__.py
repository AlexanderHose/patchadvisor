"""Shared per-user GCP client cache and tool exports."""

from contextvars import ContextVar
from functools import lru_cache
import os
from google.cloud import compute_v1, osconfig_v1, securitycenter_v2
from google.oauth2.credentials import Credentials

_user_access_token: ContextVar[str | None] = ContextVar("_user_access_token", default=None)


def set_user_access_token(token: str | None) -> None:
    """Bind the active user's Google OAuth 2.0 access token for the current agent invocation."""
    _user_access_token.set(token.strip() if token else None)


@lru_cache(maxsize=32)
def _build_client(client_cls, token: str):
    quota_project = os.getenv("GOOGLE_CLOUD_PROJECT") or None
    return client_cls(credentials=Credentials(token=token, quota_project_id=quota_project))


def _get_client(client_cls):
    token = _user_access_token.get()
    if not token:
        raise PermissionError("Missing user Google OAuth access token. Authenticate via Slack first.")
    return _build_client(client_cls, token)


def get_instances_client() -> compute_v1.InstancesClient:
    return _get_client(compute_v1.InstancesClient)


def get_disks_client() -> compute_v1.DisksClient:
    return _get_client(compute_v1.DisksClient)


def get_osconfig_client() -> osconfig_v1.OsConfigServiceClient:
    return _get_client(osconfig_v1.OsConfigServiceClient)


def get_osconfig_zonal_client() -> osconfig_v1.OsConfigZonalServiceClient:
    return _get_client(osconfig_v1.OsConfigZonalServiceClient)


def get_scc_v2_client() -> securitycenter_v2.SecurityCenterClient:
    return _get_client(securitycenter_v2.SecurityCenterClient)


def get_boot_disk_info(instance: compute_v1.Instance) -> tuple[str | None, str | None]:
    """Return (boot_disk_name, device_name) from a Compute Engine Instance."""
    for disk in instance.disks:
        if disk.boot:
            disk_name = disk.source.split("/")[-1] if disk.source else None
            return disk_name, disk.device_name
    return None, None


from .health_check import check_vm_runtime_health, verify_patch_compliance
from .osconfig import (
    get_guest_inventory,
    get_vm_instance,
    get_vulnerability_report,
    list_project_vms,
)
from .osconfig_patch import apply_osconfig_patch
from .scc import get_scc_findings
from .snapshot import create_boot_disk_snapshot, rollback_vm_to_snapshot


__all__ = [
    "set_user_access_token",
    "get_instances_client",
    "get_disks_client",
    "get_osconfig_client",
    "get_osconfig_zonal_client",
    "get_scc_v2_client",
    "get_boot_disk_info",
    "list_project_vms",
    "get_vm_instance",
    "get_vulnerability_report",
    "get_guest_inventory",
    "get_scc_findings",
    "create_boot_disk_snapshot",
    "rollback_vm_to_snapshot",
    "apply_osconfig_patch",
    "check_vm_runtime_health",
    "verify_patch_compliance",
]

