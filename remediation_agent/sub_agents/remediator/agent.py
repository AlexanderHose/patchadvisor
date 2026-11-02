"""Remediator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import preload_memory

from .prompt import REMEDIATOR_INSTR
from ...tools import (
    apply_osconfig_patch,
    create_boot_disk_snapshot,
    get_firewall_rule,
    get_vm_instance,
    get_vulnerability_report,
    list_disk_snapshots,
    list_project_vms,
    rollback_vm_to_snapshot,
    set_scc_finding_mute,
    set_vm_metadata,
    update_firewall_rule,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

remediator_agent = Agent(
    name="remediator_agent",
    description="Executes confirmation-gated VM and posture remediation: snapshots boot disks, applies OS Config patch jobs, updates VPC firewall rules, hardens VM metadata, mutes mitigated SCC findings, and rolls back snapshots when confirmed.",
    model=MODEL,
    instruction=REMEDIATOR_INSTR,
    output_key="remediation_attempt",
    tools=[
        list_project_vms,
        get_vm_instance,
        get_vulnerability_report,
        get_firewall_rule,
        list_disk_snapshots,
        create_boot_disk_snapshot,
        apply_osconfig_patch,
        rollback_vm_to_snapshot,
        update_firewall_rule,
        set_vm_metadata,
        set_scc_finding_mute,
        preload_memory,
    ],
)
