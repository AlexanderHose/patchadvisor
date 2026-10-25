# AGENTS.md: PatchAdvisor Architecture & Engineering Specification

This specification governs all code, tools, prompts, and sub-agents in this repository. Every change must adhere to these boundaries.

---

## 1. System Architecture & Component Boundaries

PatchAdvisor has two runtime components with a strict separation of concerns:

1. **Cloud Run Slack Gateway ([`server.py`](server.py))**
   A thin FastAPI proxy that connects Slack to Vertex AI Agent Engine.
   * **Allowed responsibilities:**
     * Verify Slack request signatures (`SLACK_SIGNING_SECRET`).
     * Authenticate Slack users via 3-legged Google OAuth 2.0 + PKCE (`GET /auth/google/login`, `GET /auth/google/callback`) using 1-hour online access tokens (`access_type=online`, no refresh tokens) and pass the token out-of-band in `state_delta={"temp:gcp_access_token": token}`.
     * Map a Slack thread (`channel_id`, `thread_ts`) to a Vertex AI Agent Engine `session_id` and `fleet:<project_id>` Memory Bank scope.
     * Forward user messages and button-triggered prompts to the reasoning engine endpoint via SSE (`stream_query`).
     * Update a single Slack status message with live tool-call progress and render the final markdown response into Slack Block Kit sections (`---` splits into `divider` blocks).
     * Attach static 1-click prompt buttons (`Patch Tier 1`, `Patch Tier 2`, `Approve Prod Reboot`, `Rollback`, `Re-scan`) that send fixed natural-language instructions back into the active Agent Engine session.
   * **Forbidden in `server.py`:**
     * Importing or calling GCP infrastructure SDKs (`compute_v1`, `osconfig_v1`, `securitycenter_v2`).
     * Regex-scraping package names, tiers, or CVSS scores out of agent markdown responses.
     * Tracking VM inventory, discovered packages, or remediated package lists in gateway memory.
     * Custom Slack modals (`views.open` / `view_submission`) that duplicate agent state.
     * Loading `.env` files (`SLACK_BOT_TOKEN`, `SLACK_SIGNING_SECRET`, `GOOGLE_OAUTH_CLIENT_ID`, `GOOGLE_OAUTH_CLIENT_SECRET`, and `AGENT_RESOURCE_NAME` are injected at deployment via Cloud Run `--set-secrets` and `--set-env-vars`).

2. **Vertex AI Agent Engine ([`remediation_agent/`](remediation_agent))**
   The multi-agent security reasoning and orchestration runtime built on Google ADK.
   * **`root_agent` ([`remediation_agent/agent.py`](remediation_agent/agent.py)):** Binds `temp:gcp_access_token` into the tool credential `ContextVar` (`before_agent_callback`), routes investigation queries to `investigator_agent` and remediation requests to `safe_remediation_pipeline`, and persists session lessons to Vertex AI Memory Bank (`after_agent_callback`).
   * **`investigator_agent` ([`remediation_agent/sub_agents/investigator/`](remediation_agent/sub_agents/investigator)):** Performs read-only discovery, correlates Compute Engine / OS Config telemetry with Security Command Center (SCC) posture and attack exposure, and triages findings by blast radius.
   * **`safe_remediation_pipeline` (`LoopAgent` wrapping [`remediator_agent`](remediation_agent/sub_agents/remediator) and [`validator_agent`](remediation_agent/sub_agents/validator)):** Executes canary-first remediation and post-change verification across both guest OS patching (OS Config) and cloud posture/SCC findings (IAM bindings, service account keys, firewall rules), automatically rolling back on verification failure.

---

## 2. Tool Design Specification ([`remediation_agent/tools/`](remediation_agent/tools))

Tools exist to give the LLM direct visibility and actuation over GCP APIs using standard `google-cloud-*` client libraries. Do not write Python business logic for tasks the LLM handles natively.

### 2.1 Stateless, Single-Purpose SDK Wrappers
* **One GCP operation per tool:** Each tool wraps a single GCP API operation (for example, listing VMs, getting an instance, fetching a vulnerability report, fetching guest inventory, querying SCC v2 findings, creating a disk snapshot, executing a patch job). Never chain multiple unrelated API calls inside one tool to join their data in Python.
* **Per-user OAuth credentials, zero `ToolContext.state` domain state:** Every tool takes explicit domain arguments (`project_id`, `zone`, `instance_name`, etc.) and authenticates GCP SDK clients using the active Slack user's Google OAuth 2.0 `access_token` bound via `ContextVar` in [`remediation_agent/tools/__init__.py`](remediation_agent/tools/__init__.py) (failing closed if absent). Do not read or mutate `context.state` (`active_vm`, `fleet_topology`, `latest_patch_job`, `failed_packages`, `snapshots`) to pass hidden domain state between tools.
* **Current GA APIs only:** Call current GCP client versions directly (`securitycenter_v2`, `osconfig_v1`, `compute_v1`). Never add legacy `v1` fallback blocks or multi-version wrappers.

### 2.2 Hybrid Data Serialization (Context Over Transformation)
* **Single-resource and bounded calls:** Return native `proto.Message.to_dict()` or `proto.Message.to_json()` output from the GCP SDK (`compute_v1.Instance`, `osconfig_v1.PatchJob`, `compute_v1.Operation`, raw serial port console tail) with zero custom dictionary reshaping.
* **High-volume list and report calls:** For endpoints that can return hundreds of items (`osconfig_v1.VulnerabilityReport`, `osconfig_v1.Inventory`, `securitycenter_v2.ListFindingsResponse`), apply only lightweight field pruning and item caps to keep token payloads bounded.
* **Zero domain heuristics in Python:**
  * Do not classify VMs into `canary` vs. `prod` in Python. Return the raw VM name, labels, and tags so the agent determines the role.
  * Do not group or deduplicate SCC attack paths by principal in Python. Return the active findings and let the agent correlate chokepoints and toxic combinations.

---

## 3. Prompt Design & Slack Output Rules (`prompt.py`)

### 3.1 Principle-Driven Instructions
* Write prompts around security reasoning principles rather than rigid fill-in-the-blank templates:
  1. **Canary-First Progression:** Identify non-production/canary targets from VM labels, tags, or names; validate changes on canary before promoting to production; gate production host reboots behind explicit user approval.
  2. **Empirical Memory Bank Recall:** Check `<PAST_CONVERSATIONS>` for prior package failures, daemon restarts, or reboot requirements on the same OS family before planning.
  3. **Blast-Radius & Attack-Path Correlation:** Prioritize VM vulnerabilities first, enriched with SCC exposure context (public IPs, open firewall ports, exposed service account keys, toxic combinations, chokepoints). Roll up child findings sharing the same principal under the primary Critical Chokepoint.
  4. **Dynamic Sections:** Include only the output sections relevant to the user's request (for example, omit VM package tiers when the user asks for an org-wide SCC posture review, or omit SCC sections if no active SCC findings exist).

### 3.2 Slack `mrkdwn` Formatting Contract
* Format all agent responses directly in Slack `mrkdwn`:
  * Use `*bold*` for emphasis and section headers (never `**double asterisks**` or `###` markdown headings).
  * Separate major sections with `---` on its own line (converted to Slack `divider` blocks by `server.py`).
  * Never use Markdown pipe tables (`| col |`).
  * Use a compact 2-line bullet pattern for findings and packages:
    * Line 1: `• *<Concise Title Case Headline>* (<key metadata: severity/class, CVSS or Exposure Score, target resource>)`
    * Line 2: `  ↳ <Technical blast radius, attack path context, and concrete remediation>`
* **Communication Guardrails:** Active voice, direct practitioner tone, zero AI filler words, and zero em dashes.