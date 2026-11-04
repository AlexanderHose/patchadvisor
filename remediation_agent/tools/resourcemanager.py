"""Cloud Resource Manager project and organization discovery tools."""

import asyncio
from itertools import islice
import json
from . import get_organizations_client, get_projects_client


async def list_accessible_projects(query: str = "") -> str:
    """Lists active GCP projects accessible to the authenticated user.

    Args:
        query: Optional substring filter to match against project_id or display_name.
    """
    needle = query.strip().lower()
    client = get_projects_client()
    try:
        projs = await asyncio.to_thread(lambda: list(islice(client.search_projects(), 100)))
    except Exception as exc:
        return json.dumps({"error": f"Failed to search accessible projects: {exc}"}, indent=2)

    records = [
        {
            "project_id": p.project_id,
            "display_name": p.display_name,
        }
        for p in projs
        if getattr(p.state, "name", str(p.state)) == "ACTIVE"
        and (not needle or needle in (p.project_id or "").lower() or needle in (p.display_name or "").lower())
    ]
    return json.dumps({"projects_count": len(records), "projects": records[:25]}, indent=2)


async def list_accessible_organizations() -> str:
    """Lists GCP organizations accessible to the authenticated user."""
    client = get_organizations_client()
    try:
        orgs = await asyncio.to_thread(lambda: list(islice(client.search_organizations(), 25)))
    except Exception as exc:
        return json.dumps({"error": f"Failed to search accessible organizations: {exc}"}, indent=2)

    records = [
        {
            "org_id": (o.name or "").removeprefix("organizations/"),
            "display_name": o.display_name,
            "state": getattr(o.state, "name", str(o.state)),
        }
        for o in orgs
    ]
    return json.dumps({"organizations_count": len(records), "organizations": records}, indent=2)

