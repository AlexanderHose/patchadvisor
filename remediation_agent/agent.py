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
    "apply_osconfig_patch",
    "rollback_vm_to_snapshot",
    "create_boot_disk_snapshot",
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
    description="Self-healing canary-to-production remediation loop: snapshots, patches canary first, validates guest inventory and systemd health, auto-rolls back and isolates broken packages on failure, promotes verified Tier 1 and Tier 2 packages to production, and emits learned package memory.",
    sub_agents=[remediator_agent, validator_agent],
    max_iterations=3,
)

root_agent = Agent(
    name="remediation_agent",
    description="Root orchestrator for self-learning, canary-first vulnerability triage and autonomous remediation.",
    model=MODEL,
    instruction=ROOT_AGENT_INSTR,
    tools=[preload_memory],
    sub_agents=[investigator_agent, safe_remediation_pipeline],
)

for _agent in (root_agent, investigator_agent, safe_remediation_pipeline, remediator_agent, validator_agent):
    _agent.before_agent_callback = _inject_user_credentials
    _agent.after_agent_callback = _clear_user_credentials

safe_remediation_pipeline.after_agent_callback = _finalize_and_persist_memory


