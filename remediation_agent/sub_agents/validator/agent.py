"""Validator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import exit_loop, preload_memory

from .prompt import VALIDATOR_INSTR
from ...tools import (
    check_vm_runtime_health,
    get_guest_inventory,
    get_vulnerability_report,
    rollback_vm_to_snapshot,
    verify_patch_compliance,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

validator_agent = Agent(
    name="validator_agent",
    description="Performs post-remediation health checks, verifies OS Config guest inventory versions, triggers automatic snapshot rollback on failure, and controls the remediation loop.",
    model=MODEL,
    instruction=VALIDATOR_INSTR,
    output_key="validation_verdict",
    tools=[
        check_vm_runtime_health,
        verify_patch_compliance,
        get_guest_inventory,
        rollback_vm_to_snapshot,
        get_vulnerability_report,
        exit_loop,
        preload_memory,
    ],
)



