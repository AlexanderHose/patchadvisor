"""Cloud-Native Slack Gateway for Vertex AI Agent Engine."""

import asyncio
import base64
from dataclasses import dataclass
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import time
from urllib.parse import parse_qs, urlencode
from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import google.auth
import google.auth.transport.requests
import httpx
from slack_sdk import WebClient
from slack_sdk.errors import SlackApiError
from slack_sdk.signature import SignatureVerifier

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
logger = logging.getLogger("remediation-agent")

app = FastAPI(title="PatchAdvisor Slack Gateway")

SLACK_BOT_TOKEN = os.getenv("SLACK_BOT_TOKEN")
SLACK_SIGNING_SECRET = os.getenv("SLACK_SIGNING_SECRET")
AGENT_RESOURCE_NAME = os.getenv("AGENT_RESOURCE_NAME", "").strip()
_parts = AGENT_RESOURCE_NAME.split("/")
AGENT_BASE_URL = f"https://{_parts[3]}-aiplatform.googleapis.com/v1beta1/{AGENT_RESOURCE_NAME}" if len(_parts) > 3 else ""
AGENT_QUERY_URL = f"{AGENT_BASE_URL}:streamQuery" if AGENT_BASE_URL else ""
GOOGLE_OAUTH_CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID", "")
GOOGLE_OAUTH_CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET", "")
PUBLIC_GATEWAY_URL = os.getenv("PUBLIC_GATEWAY_URL", "").rstrip("/")
_GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
_GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
_GOOGLE_SCOPES = "openid email https://www.googleapis.com/auth/cloud-platform"

slack_client = WebClient(token=SLACK_BOT_TOKEN) if SLACK_BOT_TOKEN else None
_signature_verifier = SignatureVerifier(SLACK_SIGNING_SECRET) if SLACK_SIGNING_SECRET else None
_gcp_credentials = None
_default_project = None
_gcp_auth_request = google.auth.transport.requests.Request()

_ACTION_PROMPTS: dict[str, tuple[str, str]] = {
    "patch_tier_1": (
        "Remediate the Tier 1 (Zero-Downtime Live Updates) packages identified in this session using reboot_policy=NEVER. Create a pre-patch boot disk snapshot first, apply the OS Config patch job, and verify runtime health.",
        "🚀 *Tier 1 Remediation Approved:* Creating pre-patch boot disk snapshot and applying Tier 1 live updates...",
    ),
    "patch_tier_2": (
        "Remediate the Tier 2 (Daemon Restarts) packages identified in this session using reboot_policy=NEVER. Create a pre-patch boot disk snapshot first, apply the OS Config patch job, and verify runtime health.",
        "🚀 *Tier 2 Remediation Approved:* Creating pre-patch boot disk snapshot and applying Tier 2 updates...",
    ),
    "approve_prod_reboot": (
        "Approve and execute host reboot remediation (reboot_policy=REBOOT_IF_NEEDED) for the pending Tier 3 / reboot-required packages in this session. Create a pre-patch boot disk snapshot first and verify post-reboot runtime health.",
        "🔴 *Host Reboot Approved:* Creating pre-patch boot disk snapshot and applying updates with REBOOT_IF_NEEDED...",
    ),
    "rollback_snapshot": (
        "Immediately roll back the target VM in this session to its latest pre-patch boot disk snapshot using rollback_vm_to_snapshot and verify runtime health.",
        "⏪ *Rollback Initiated:* Restoring target VM boot disk from pre-patch snapshot...",
    ),
    "rescan_vulnerabilities": (
        "Re-scan and investigate the active target in this session.",
        "🔄 *Re-scanning target vulnerability and SCC posture...*",
    ),
}


@dataclass
class ThreadSession:
    scope: str | None = None
    agent_session_id: str | None = None


@dataclass
class UserToken:
    access_token: str
    expires_at: float


ACTIVE_SESSIONS: dict[str, ThreadSession] = {}
USER_TOKENS: dict[str, UserToken] = {}
AUTH_RESPONSE_URLS: dict[str, str] = {}


def get_session(thread_ts: str) -> ThreadSession:
    if thread_ts not in ACTIVE_SESSIONS:
        if len(ACTIVE_SESSIONS) >= 500:
            ACTIVE_SESSIONS.pop(next(iter(ACTIVE_SESSIONS)), None)
        ACTIVE_SESSIONS[thread_ts] = ThreadSession()
    return ACTIVE_SESSIONS[thread_ts]


def get_user_token(slack_user_id: str) -> str | None:
    entry = USER_TOKENS.get(slack_user_id)
    if entry and entry.expires_at > time.time() + 30:
        return entry.access_token
    USER_TOKENS.pop(slack_user_id, None)
    return None


def _gateway_base_url(request: Request) -> str:
    if PUBLIC_GATEWAY_URL:
        return PUBLIC_GATEWAY_URL
    proto = request.headers.get("x-forwarded-proto", request.url.scheme or "https")
    host = request.headers.get("host") or request.url.netloc
    return f"{proto}://{host}".rstrip("/")


def _sign_oauth_state(payload: dict) -> str:
    if not SLACK_SIGNING_SECRET:
        raise RuntimeError("SLACK_SIGNING_SECRET is not configured.")
    payload["n"] = secrets.token_hex(8)
    raw = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode()).rstrip(b"=")
    sig = hmac.new(SLACK_SIGNING_SECRET.encode(), raw, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(sig).rstrip(b"=")
    return f"{raw.decode()}.{sig_b64.decode()}"


def _verify_oauth_state(state: str) -> dict | None:
    if not SLACK_SIGNING_SECRET or "." not in state:
        return None
    raw_str, sig_str = state.split(".", 1)
    try:
        expected = hmac.new(SLACK_SIGNING_SECRET.encode(), raw_str.encode(), hashlib.sha256).digest()
        expected_b64 = base64.urlsafe_b64encode(expected).rstrip(b"=").decode()
        if not hmac.compare_digest(sig_str, expected_b64):
            return None
        padded = raw_str + "=" * (-len(raw_str) % 4)
        data = json.loads(base64.urlsafe_b64decode(padded))
        if not isinstance(data, dict):
            return None
        if time.time() - data.get("ts", 0) > 600:
            return None
        if not str(data.get("r", "")).endswith("/auth/google/callback"):
            return None
        return data
    except Exception:
        return None


def _derive_pkce_verifier(state: str) -> str:
    if not SLACK_SIGNING_SECRET:
        raise RuntimeError("SLACK_SIGNING_SECRET is not configured.")
    digest = hmac.new(SLACK_SIGNING_SECRET.encode(), f"pkce:{state}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


async def slack_post(channel: str, thread_ts: str | None = None, **kwargs) -> dict:
    if not slack_client:
        return {}
    return await asyncio.to_thread(slack_client.chat_postMessage, channel=channel, thread_ts=thread_ts, **kwargs)


async def prompt_google_login(
    request: Request,
    slack_user_id: str,
    channel_id: str,
    thread_ts: str,
    prompt: str,
    ack_text: str = "🧠 Initializing PatchAdvisor planner and recalling fleet Memory Bank...",
    in_existing_thread: bool = False,
    response_url: str = "",
) -> None:
    if not slack_client:
        return
    base_url = _gateway_base_url(request)
    state_payload = {
        "u": slack_user_id,
        "c": channel_id,
        "t": thread_ts,
        "p": prompt,
        "a": ack_text,
        "r": f"{base_url}/auth/google/callback",
        "ts": int(time.time()),
    }
    if response_url and response_url.startswith("https://hooks.slack.com/"):
        state_payload["ru"] = response_url
    state = _sign_oauth_state(state_payload)
    login_url = f"{base_url}/auth/google/login?state={state}"
    blocks = [
        {
            "type": "section",
            "text": {
                "type": "mrkdwn",
                "text": "🔐 *Google Cloud Authentication Required*\nSign in with your Google account so PatchAdvisor can execute this request using your IAM permissions (1-hour session).",
            },
        },
        {
            "type": "actions",
            "block_id": "google_auth_actions",
            "elements": [
                {
                    "type": "button",
                    "text": {"type": "plain_text", "text": "🔑 Sign in with Google Cloud", "emoji": True},
                    "style": "primary",
                    "url": login_url,
                    "action_id": "google_oauth_login",
                }
            ],
        },
    ]
    ephemeral_kwargs: dict = {
        "channel": channel_id,
        "user": slack_user_id,
        "text": f"Authenticate with Google Cloud: {login_url}",
        "blocks": blocks,
    }
    if in_existing_thread:
        ephemeral_kwargs["thread_ts"] = thread_ts
    await asyncio.to_thread(slack_client.chat_postEphemeral, **ephemeral_kwargs)


async def slack_update(channel: str, ts: str | None, **kwargs) -> None:
    if not slack_client or not ts:
        return
    try:
        await asyncio.to_thread(slack_client.chat_update, channel=channel, ts=ts, **kwargs)
    except Exception:
        pass


async def get_agent_headers() -> dict[str, str]:
    global _gcp_credentials, _default_project
    if _gcp_credentials is None:
        _gcp_credentials, _default_project = await asyncio.to_thread(
            google.auth.default, scopes=["https://www.googleapis.com/auth/cloud-platform"]
        )
    if not _gcp_credentials.valid:
        await asyncio.to_thread(_gcp_credentials.refresh, _gcp_auth_request)
    return {"Authorization": f"Bearer {_gcp_credentials.token}", "Content-Type": "application/json"}


def get_fleet_scope(session: ThreadSession) -> str:
    return f"fleet:{session.scope or _default_project or 'default'}"





async def ensure_agent_session(session: ThreadSession, channel_id: str, thread_ts: str) -> str | None:
    if session.agent_session_id or not AGENT_BASE_URL:
        return session.agent_session_id
    try:
        headers = await get_agent_headers()
        fleet_scope = get_fleet_scope(session)

        # Reconnect to existing session on Agent Engine if one exists for this thread
        async with httpx.AsyncClient(timeout=10.0) as client:
            list_resp = await client.get(
                f"{AGENT_BASE_URL}/sessions?filter=userId=\"{fleet_scope}\"&pageSize=20", headers=headers
            )
            if list_resp.status_code == 200:
                sessions = list_resp.json().get("sessions", [])
                matches = [
                    s for s in sessions
                    if (s.get("sessionState") or {}).get("slack_thread_ts") == thread_ts
                    and (not session.scope or s.get("userId") == fleet_scope)
                ]
                if matches:
                    matches.sort(key=lambda s: s.get("updateTime", s.get("createTime", "")), reverse=True)
                    latest = matches[0]
                    name = latest.get("name", "")
                    session.agent_session_id = name.split("/sessions/")[-1].split("/")[0]
                    if not session.scope and latest.get("userId", "").startswith("fleet:"):
                        session.scope = latest["userId"].removeprefix("fleet:")
                    logger.info(f"Reconnected Agent Engine session {session.agent_session_id} for thread {thread_ts}")
                    return session.agent_session_id

            # Create a new session if none exists
            payload = {
                "user_id": fleet_scope,
                "session_state": {"slack_thread_ts": thread_ts, "slack_channel_id": channel_id},
            }
            resp = await client.post(f"{AGENT_BASE_URL}/sessions", json=payload, headers=headers)
            if resp.status_code == 200:
                data = resp.json()
                name = data.get("response", {}).get("name") or data.get("name", "")
                session.agent_session_id = name.split("/sessions/")[-1].split("/")[0]
                logger.info(f"Created Agent Engine session {session.agent_session_id} for thread {thread_ts}")
                return session.agent_session_id
    except Exception as exc:
        logger.warning(f"Failed to ensure Agent Engine session: {exc}")
    return None


def split_slack_message(text: str, max_chars: int = 2900) -> list[str]:
    chunks, remaining = [], text.strip()
    while remaining:
        if len(remaining) <= max_chars:
            chunks.append(remaining)
            break
        idx = max(
            remaining.rfind("\n\n", 0, max_chars),
            remaining.rfind("\n•", 0, max_chars),
            remaining.rfind("\n", 0, max_chars),
        )
        idx = idx if idx > 0 else max_chars
        chunks.append(remaining[:idx].strip())
        remaining = remaining[idx:].strip()
    return [c for c in chunks if c]


def _btn(label: str, action_id: str, style: str | None = None) -> dict:
    b: dict = {"type": "button", "text": {"type": "plain_text", "text": label, "emoji": True}, "action_id": action_id}
    if style:
        b["style"] = style
    return b


def build_action_buttons(report_text: str) -> list[dict]:
    if any(k in report_text for k in ("🛠️ Remediation Report", "✅ Post-Patch Verification")):
        btns = [_btn("🔄 Re-scan", "rescan_vulnerabilities")]
        if any(k in report_text for k in ("Reboot Required", "reboot_required=True")):
            btns.append(_btn("🔴 Approve Prod Reboot", "approve_prod_reboot", "primary"))
        btns.append(_btn("⏪ Rollback", "rollback_snapshot", "danger"))
        return btns

    btns = []
    if "Tier 1" in report_text:
        btns.append(_btn("🟢 Patch Tier 1", "patch_tier_1", "primary"))
    if "Tier 2" in report_text:
        btns.append(_btn("🟡 Patch Tier 2", "patch_tier_2"))
    if "Tier 3" in report_text:
        btns.append(_btn("🔴 Approve Prod Reboot", "approve_prod_reboot", "danger"))
    if any(k in report_text for k in ("*📊 Scope*", "Executive Verdict")):
        btns.append(_btn("🔄 Re-scan", "rescan_vulnerabilities"))
    return btns


def markdown_to_slack_blocks(report_text: str) -> list[dict]:
    if not report_text or not report_text.strip():
        return []
    sections = [s.strip() for s in re.split(r"(?:^|\n)---+(?:\n|$)", report_text.strip()) if s.strip()]
    blocks: list[dict] = []
    for sec in sections:
        if blocks:
            blocks.append({"type": "divider"})
        for chunk in split_slack_message(sec, max_chars=2900):
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": chunk}})

    actions = build_action_buttons(report_text)
    max_content_blocks = 48 if actions else 50
    if len(blocks) > max_content_blocks:
        blocks = blocks[:max_content_blocks]

    if actions:
        if not blocks or blocks[-1].get("type") != "divider":
            blocks.append({"type": "divider"})
        blocks.append({"type": "actions", "block_id": "remediation_actions", "elements": actions})
    return blocks[:50]


def format_sse_progress(event: dict) -> str | None:
    parts = event.get("content", {}).get("parts", [])
    for part in parts:
        fc = part.get("function_call") or part.get("functionCall")
        if isinstance(fc, dict) and fc.get("name"):
            args = fc.get("args", {}) or {}
            target = args.get("instance_name") or args.get("agent_name") or args.get("project_id") or ""
            return f"🔧 Running `{fc['name']}`{f' (`{target}`)' if target else ''}..."
    if any(p.get("thought") for p in parts):
        return f"🧠 *[{event.get('author') or 'agent'}]* Synthesizing findings..."
    return None


async def query_deployed_agent(
    prompt: str,
    session_id: str | None,
    scope: str,
    channel_id: str,
    status_ts: str | None,
    user_token: str,
) -> str:
    headers = await get_agent_headers()
    input_payload: dict = {
        "message": prompt,
        "user_id": scope,
        "state_delta": {"temp:gcp_access_token": user_token},
    }
    if session_id:
        input_payload["session_id"] = session_id

    text_parts, thought_parts, progress_log = [], [], []
    last_update = 0.0
    start_time = time.time()

    async with httpx.AsyncClient(timeout=360.0) as client:
        async with client.stream(
            "POST", AGENT_QUERY_URL, json={"class_method": "stream_query", "input": input_payload}, headers=headers
        ) as resp:
            if resp.status_code != 200:
                body = (await resp.aread()).decode(errors="replace")
                logger.error(f"Agent Engine HTTP {resp.status_code}: {body}")
                raise RuntimeError(f"Agent Engine HTTP {resp.status_code}")

            async for line in resp.aiter_lines():
                clean = line.strip().removeprefix("data:").strip()
                if not clean:
                    continue
                try:
                    event = json.loads(clean)
                except json.JSONDecodeError:
                    continue
                if not isinstance(event, dict):
                    continue

                if "error" in event:
                    err = event["error"]
                    text_parts.append(f"❌ Error: {err.get('message', err) if isinstance(err, dict) else err}")

                step = format_sse_progress(event)
                if step and (not progress_log or progress_log[-1] != step):
                    progress_log.append(step)
                    now = time.time()
                    if now - last_update >= 1.0:
                        last_update = now
                        await slack_update(
                            channel_id, status_ts, text="⚡ *Agent Live Progress:*\n" + "\n".join(progress_log[-6:])
                        )

                parts = event.get("content", {}).get("parts", [])
                if any(p.get("function_call") or p.get("functionCall") for p in parts):
                    continue
                for p in parts:
                    if p.get("text"):
                        (thought_parts if p.get("thought") else text_parts).append(p["text"])

    elapsed = round(time.time() - start_time, 1)
    steps = max(1, len(progress_log))
    summary = f"✅ *Agent Execution Complete* · {steps} step{'s' if steps != 1 else ''} in `{elapsed}s` · Scope: `{scope}`"
    await slack_update(
        channel_id,
        status_ts,
        text=summary,
        blocks=[{"type": "context", "elements": [{"type": "mrkdwn", "text": summary}]}],
    )
    return "".join(text_parts).strip() or "".join(thought_parts).strip()


async def execute_agent_and_reply(
    channel_id: str,
    thread_ts: str,
    prompt: str,
    ack_text: str = "🧠 Initializing PatchAdvisor planner and recalling fleet Memory Bank...",
    user_token: str = "",
) -> None:
    if not slack_client:
        return

    session = get_session(thread_ts)
    scope_m = re.search(r"(?:project|org(?:anization)?)[=:\s]+([a-zA-Z0-9_\-]+)", prompt, re.IGNORECASE)
    if scope_m and scope_m.group(1) != session.scope:
        session.scope = scope_m.group(1)
        session.agent_session_id = None

    ack = await slack_post(channel_id, thread_ts, text=ack_text)
    agent_session_id = await ensure_agent_session(session, channel_id, thread_ts)
    scope = get_fleet_scope(session)

    try:
        report = await query_deployed_agent(
            prompt, agent_session_id, scope, channel_id, ack.get("ts"), user_token
        )
        if not report:
            report = "⚠️ Agent execution completed, but no report output was generated."

        blocks = markdown_to_slack_blocks(report)
        try:
            if blocks:
                await slack_post(channel_id, thread_ts, text="🛡️ PatchAdvisor Security Report", blocks=blocks)
            else:
                for chunk in split_slack_message(report, max_chars=3800):
                    await slack_post(channel_id, thread_ts, text=chunk)
        except SlackApiError:
            for chunk in split_slack_message(report, max_chars=3800):
                await slack_post(channel_id, thread_ts, text=chunk)


    except Exception:
        logger.exception("Error querying Agent Engine:")
        await slack_post(
            channel_id,
            thread_ts,
            text="❌ Internal error communicating with PatchAdvisor Agent Engine. Check Cloud Logging for details.",
        )


@app.get("/health")
def health() -> dict:
    return {"status": "ok"}


@app.get("/auth/google/login")
async def google_oauth_login(state: str = ""):
    pending = _verify_oauth_state(state)
    if not pending:
        raise HTTPException(status_code=400, detail="Expired or invalid OAuth state. Trigger the command in Slack again.")
    if not GOOGLE_OAUTH_CLIENT_ID or not GOOGLE_OAUTH_CLIENT_SECRET:
        raise HTTPException(status_code=500, detail="GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET are not configured.")

    verifier = _derive_pkce_verifier(state)
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    code_challenge = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
    params = {
        "client_id": GOOGLE_OAUTH_CLIENT_ID,
        "redirect_uri": pending["r"],
        "response_type": "code",
        "scope": _GOOGLE_SCOPES,
        "access_type": "online",
        "prompt": "select_account",
        "state": state,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    return RedirectResponse(f"{_GOOGLE_AUTH_URL}?{urlencode(params)}")


@app.get("/auth/google/callback")
async def google_oauth_callback(background_tasks: BackgroundTasks, code: str = "", state: str = "", error: str = ""):
    if error:
        return HTMLResponse(f"<h3>Authentication cancelled: {html.escape(error)}</h3>", status_code=400)
    if not GOOGLE_OAUTH_CLIENT_ID or not GOOGLE_OAUTH_CLIENT_SECRET:
        return HTMLResponse("<h3>OAuth client credentials are not configured.</h3>", status_code=500)
    pending = _verify_oauth_state(state)
    if not pending or not code:
        return HTMLResponse("<h3>Invalid or expired login state. Please retry from Slack.</h3>", status_code=400)

    async with httpx.AsyncClient(timeout=15.0) as client:
        resp = await client.post(
            _GOOGLE_TOKEN_URL,
            data={
                "client_id": GOOGLE_OAUTH_CLIENT_ID,
                "client_secret": GOOGLE_OAUTH_CLIENT_SECRET,
                "code": code,
                "code_verifier": _derive_pkce_verifier(state),
                "grant_type": "authorization_code",
                "redirect_uri": pending["r"],
            },
        )
    if resp.status_code != 200:
        logger.error(f"Google OAuth token exchange failed ({resp.status_code}): {resp.text}")
        return HTMLResponse("<h3>Failed to exchange Google OAuth token.</h3>", status_code=400)

    token_data = resp.json()
    access_token = token_data.get("access_token", "")
    expires_in = int(token_data.get("expires_in", 3600))
    if not access_token:
        return HTMLResponse("<h3>No access token returned by Google.</h3>", status_code=400)

    if len(USER_TOKENS) >= 500:
        USER_TOKENS.pop(next(iter(USER_TOKENS)), None)
    USER_TOKENS[pending["u"]] = UserToken(access_token=access_token, expires_at=time.time() + expires_in)

    resp_url = AUTH_RESPONSE_URLS.pop(pending["u"], None) or pending.get("ru")
    if resp_url and resp_url.startswith("https://hooks.slack.com/"):
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                res = await client.post(resp_url, json={"delete_original": True})
                logger.info(f"Deleted ephemeral auth message for {pending['u']}: HTTP {res.status_code}")
        except Exception as exc:
            logger.warning(f"Failed to delete ephemeral auth message: {exc}")

    background_tasks.add_task(
        execute_agent_and_reply,
        pending["c"],
        pending["t"],
        pending["p"],
        pending["a"],
        access_token,
    )
    return HTMLResponse(
        "<html><body style='font-family:sans-serif;text-align:center;padding-top:4rem;'>"
        "<h2>✅ Google Cloud Authentication Complete</h2>"
        "<p>Your 1-hour session is active and PatchAdvisor is now executing your request in Slack. You can close this tab.</p>"
        "</body></html>",
        headers={"X-Content-Type-Options": "nosniff", "X-Frame-Options": "DENY"},
    )


@app.post("/slack/events")
@app.post("/slack/actions")
async def slack_events(
    request: Request,
    background_tasks: BackgroundTasks,
    x_slack_request_timestamp: str = Header(None),
    x_slack_signature: str = Header(None),
    x_slack_retry_num: str = Header(None),
):
    if x_slack_retry_num:
        return JSONResponse(content={"status": "ignored_retry"}, status_code=200)

    body = await request.body()
    ts = x_slack_request_timestamp or ""
    sig = x_slack_signature or ""
    if not (_signature_verifier and ts.isdigit() and _signature_verifier.is_valid(body=body, timestamp=ts, signature=sig)):
        raise HTTPException(status_code=401, detail="Invalid Slack signature")

    if "application/x-www-form-urlencoded" in request.headers.get("content-type", ""):
        form = parse_qs(body.decode("utf-8", errors="replace"))
        payload = json.loads(form.get("payload", ["{}"])[0])
        if payload.get("type") == "block_actions" and payload.get("actions"):
            action_id = payload["actions"][0].get("action_id", "")
            slack_user_id = payload.get("user", {}).get("id", "")
            if action_id == "google_oauth_login":
                resp_url = payload.get("response_url", "")
                if slack_user_id and resp_url.startswith("https://hooks.slack.com/"):
                    if len(AUTH_RESPONSE_URLS) >= 500:
                        AUTH_RESPONSE_URLS.pop(next(iter(AUTH_RESPONSE_URLS)), None)
                    AUTH_RESPONSE_URLS[slack_user_id] = resp_url
                    logger.info(f"Captured ephemeral auth response_url for user {slack_user_id}")
                return JSONResponse(content={"status": "oauth_redirect"}, status_code=200)
            channel_id = payload.get("channel", {}).get("id")
            thread_ts = payload.get("container", {}).get("thread_ts") or payload.get("container", {}).get("message_ts")
            if action_id in _ACTION_PROMPTS and channel_id and thread_ts and slack_user_id:
                prompt, ack = _ACTION_PROMPTS[action_id]
                user_token = get_user_token(slack_user_id)
                if not user_token:
                    await prompt_google_login(
                        request,
                        slack_user_id,
                        channel_id,
                        thread_ts,
                        prompt,
                        ack,
                        in_existing_thread=True,
                    )
                else:
                    background_tasks.add_task(execute_agent_and_reply, channel_id, thread_ts, prompt, ack, user_token)
        return JSONResponse(content={"status": "accepted"}, status_code=200)

    data = json.loads(body)
    if data.get("type") == "url_verification":
        return {"challenge": data.get("challenge")}

    event = data.get("event", {})
    if event.get("type") == "app_mention":
        slack_user_id = event.get("user", "")
        channel_id = event.get("channel")
        thread_ts = event.get("thread_ts")
        clean_text = re.sub(r"<@[A-Z0-9]+>", "", event.get("text", "")).strip()

        if not clean_text or (clean_text.lower() in {"help", "hi", "hello"} and not thread_ts):
            await slack_post(
                channel_id,
                thread_ts or event.get("ts"),
                text="Specify a VM instance or GCP project/organization to triage.\nExample: `@PatchAdvisor investigate <instance-name> in project <project-id> and zone <zone>`",
            )
            return JSONResponse(content={"status": "help_provided"}, status_code=200)

        is_in_thread = bool(thread_ts)
        if not thread_ts:
            thread_ts = event.get("ts")

        user_token = get_user_token(slack_user_id)
        if not user_token:
            await prompt_google_login(
                request,
                slack_user_id,
                channel_id,
                thread_ts,
                clean_text,
                in_existing_thread=is_in_thread,
            )
        else:
            background_tasks.add_task(
                execute_agent_and_reply,
                channel_id,
                thread_ts,
                clean_text,
                user_token=user_token,
            )

    return JSONResponse(content={"status": "accepted"}, status_code=200)
