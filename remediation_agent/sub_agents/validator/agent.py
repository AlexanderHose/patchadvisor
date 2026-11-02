"""Validator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import exit_loop, preload_memory

from .prompt import VALIDATOR_INSTR
from ...tools import (
    check_vm_runtime_health,
    get_firewall_rule,
    get_guest_inventory,
    get_vm_system_logs,
    get_vulnerability_report,
    list_disk_snapshots,
    rollback_vm_to_snapshot,
    verify_patch_compliance,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

validator_agent = Agent(
    name="validator_agent",
    description="Performs post-remediation health checks, inspects Cloud Logging system logs, verifies OS Config guest inventory versions and firewall rules, and controls the remediation loop.",
    model=MODEL,
    instruction=VALIDATOR_INSTR,
    output_key="validation_verdict",
    tools=[
        check_vm_runtime_health,
        get_vm_system_logs,
        verify_patch_compliance,
        get_guest_inventory,
        get_vulnerability_report,
        get_firewall_rule,
        list_disk_snapshots,
        rollback_vm_to_snapshot,
        exit_loop,
        preload_memory,
    ],
)
