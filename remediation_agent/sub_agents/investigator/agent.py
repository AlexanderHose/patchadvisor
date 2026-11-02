"""Investigator sub-agent definition."""

import os
from google.adk.agents import Agent
from google.adk.tools import preload_memory

from .prompt import INVESTIGATOR_INSTR
from ...tools import (
    get_firewall_rule,
    get_guest_inventory,
    get_scc_attack_paths,
    get_scc_findings,
    get_vm_instance,
    get_vm_system_logs,
    get_vulnerability_report,
    list_accessible_organizations,
    list_accessible_projects,
    list_disk_snapshots,
    list_project_vms,
)

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

investigator_agent = Agent(
    name="investigator_agent",
    description="Read-only discovery agent: resolves accessible GCP projects and organizations, and inspects VMs, OS Config vulnerabilities, VPC firewall rules, system logs, and Security Command Center (SCC) findings and attack paths.",
    model=MODEL,
    instruction=INVESTIGATOR_INSTR,
    tools=[
        list_accessible_projects,
        list_accessible_organizations,
        list_project_vms,
        get_vm_instance,
        get_vulnerability_report,
        get_guest_inventory,
        get_scc_findings,
        get_scc_attack_paths,
        get_firewall_rule,
        get_vm_system_logs,
        list_disk_snapshots,
        preload_memory,
    ],
)
