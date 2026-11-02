import os
from google.adk.agents import Agent, LoopAgent
from google.adk.tools import preload_memory

from .prompt import ROOT_AGENT_INSTR
from .sub_agents.investigator.agent import investigator_agent
from .sub_agents.remediator.agent import remediator_agent
from .sub_agents.validator.agent import validator_agent
from .tools import set_user_access_token

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")


def _inject_user_credentials(callback_context):
    """Bind the ephemeral user Google OAuth token from invocation state into the tool ContextVar."""
    set_user_access_token(callback_context.state.get("temp:gcp_access_token"))
    return None


def _clear_user_credentials(callback_context):
    """Clear the thread-local user OAuth token after an agent step finishes."""
    set_user_access_token(None)
    return None


_MUTATING_TOOLS = frozenset({
    "create_boot_disk_snapshot",
    "apply_osconfig_patch",
    "rollback_vm_to_snapshot",
    "update_firewall_rule",
    "set_vm_metadata",
    "set_scc_finding_mute",
})


def _has_mutating_actions(events) -> bool:
    for ev in events:
        if hasattr(ev, "get_function_calls"):
            for fc in ev.get_function_calls():
                if getattr(fc, "name", None) in _MUTATING_TOOLS:
                    return True
        content = getattr(ev, "content", None)
        parts = getattr(content, "parts", []) if content else []
        for p in parts:
            fc = getattr(p, "function_call", None) or getattr(p, "functionCall", None)
            name = getattr(fc, "name", None) if fc else None
            if name in _MUTATING_TOOLS:
                return True
    return False


async def _finalize_and_persist_memory(callback_context):
    """Clear the thread-local user OAuth token and persist memory only if mutating actions occurred."""
    set_user_access_token(None)
    try:
        events = callback_context.session.events[-15:]
        if events and _has_mutating_actions(events):
            await callback_context.add_events_to_memory(
                events=events,
                custom_metadata={"wait_for_completion": False},
            )
    except Exception:
        pass
    return None


safe_remediation_pipeline = LoopAgent(
    name="safe_remediation_pipeline",
    description="Confirmation-gated remediation and verification loop: executes confirmed canary or production OS patching, firewall containment, VM metadata hardening, SCC finding mutes, or snapshot rollbacks, then verifies runtime and log health.",
    sub_agents=[remediator_agent, validator_agent],
    max_iterations=2,
)

root_agent = Agent(
    name="remediation_agent",
    description="Root orchestrator for read-only vulnerability/SCC triage and confirmation-gated remediation.",
    model=MODEL,
    instruction=ROOT_AGENT_INSTR,
    tools=[preload_memory],
    sub_agents=[investigator_agent, safe_remediation_pipeline],
)

for _agent in (root_agent, investigator_agent, safe_remediation_pipeline, remediator_agent, validator_agent):
    _agent.before_agent_callback = _inject_user_credentials
    _agent.after_agent_callback = _clear_user_credentials

safe_remediation_pipeline.after_agent_callback = _finalize_and_persist_memory
