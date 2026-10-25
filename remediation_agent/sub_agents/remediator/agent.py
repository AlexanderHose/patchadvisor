"""Remediator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import preload_memory

from .prompt import REMEDIATOR_INSTR
from ...tools import (
    apply_osconfig_patch,
    create_boot_disk_snapshot,
    get_vm_instance,
    get_vulnerability_report,
    list_project_vms,
    rollback_vm_to_snapshot,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

remediator_agent = Agent(
    name="remediator_agent",
    description="Executes canary-first VM remediation: discovers canary vs. prod VMs, takes pre-patch boot disk snapshots, applies OS Config patch jobs, and promotes verified packages to production.",
    model=MODEL,
    instruction=REMEDIATOR_INSTR,
    output_key="remediation_attempt",
    tools=[
        list_project_vms,
        get_vm_instance,
        get_vulnerability_report,
        create_boot_disk_snapshot,
        apply_osconfig_patch,
        rollback_vm_to_snapshot,
        preload_memory,
    ],
)


