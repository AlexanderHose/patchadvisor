"""VPC firewall inspection and containment tools."""

import asyncio
import json
import proto
from google.cloud import compute_v1
from . import get_firewalls_client


async def get_firewall_rule(project_id: str, firewall_rule_name: str) -> str:
    """Retrieves a Compute Engine VPC firewall rule configuration.

    Args:
        project_id: GCP project ID.
        firewall_rule_name: Name of the VPC firewall rule.
    """
    client = get_firewalls_client()
    try:
        rule = await asyncio.to_thread(client.get, project=project_id, firewall=firewall_rule_name.strip())
        return proto.Message.to_json(rule, use_integers_for_enums=False)
    except Exception as exc:
        return json.dumps({"error": f"Failed to retrieve firewall rule '{firewall_rule_name}': {exc}"}, indent=2)


async def update_firewall_rule(
    project_id: str,
    firewall_rule_name: str,
    source_ranges: list[str] | None = None,
    disabled: bool | None = None,
) -> str:
    """Updates a Compute Engine VPC firewall rule's source ranges or disabled state.

    Requires explicit operator confirmation before execution.

    Args:
        project_id: GCP project ID.
        firewall_rule_name: Name of the VPC firewall rule to patch.
        source_ranges: Optional replacement list of source CIDR ranges (e.g. ['35.235.240.0/20']).
        disabled: Optional boolean to disable (True) or enable (False) the firewall rule.
    """
    if source_ranges is None and disabled is None:
        return json.dumps({"error": "Specify source_ranges and/or disabled to update the firewall rule."})

    rule_name = firewall_rule_name.strip()
    patch_kwargs: dict = {"name": rule_name}
    if source_ranges is not None:
        patch_kwargs["source_ranges"] = [r.strip() for r in source_ranges if r.strip()]
    if disabled is not None:
        patch_kwargs["disabled"] = bool(disabled)

    client = get_firewalls_client()
    try:
        operation = await asyncio.to_thread(
            client.patch,
            project=project_id,
            firewall=rule_name,
            firewall_resource=compute_v1.Firewall(**patch_kwargs),
        )
        await asyncio.to_thread(operation.result, timeout=120)
        if getattr(operation, "error_code", None):
            return json.dumps({
                "status": "FAILED",
                "firewall_rule": rule_name,
                "error": f"{operation.error_code}: {operation.error_message}",
            }, indent=2)
        return json.dumps({
            "status": "SUCCESS",
            "firewall_rule": rule_name,
            "updated_fields": {k: v for k, v in patch_kwargs.items() if k != "name"},
        }, indent=2)
    except Exception as exc:
        return json.dumps({"status": "FAILED", "firewall_rule": rule_name, "error": str(exc)}, indent=2)
