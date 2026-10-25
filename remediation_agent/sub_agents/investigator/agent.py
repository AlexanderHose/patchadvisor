"""Investigator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import preload_memory

from .prompt import INVESTIGATOR_INSTR
from ...tools import (
    get_guest_inventory,
    get_scc_findings,
    get_vm_instance,
    get_vulnerability_report,
    list_project_vms,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

investigator_agent = Agent(
    name="investigator_agent",
    description="Discovers project VMs, queries Security Command Center (SCC) findings across projects or organizations, recalls fleet memory, and triages unpatched vulnerabilities by operational blast radius and attack exposure.",
    model=MODEL,
    instruction=INVESTIGATOR_INSTR,
    tools=[
        list_project_vms,
        get_vm_instance,
        get_vulnerability_report,
        get_guest_inventory,
        get_scc_findings,
        preload_memory,
    ],
)


