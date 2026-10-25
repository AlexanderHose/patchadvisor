import os
from dotenv import load_dotenv

load_dotenv()

try:
    import google.auth
    _, default_project = google.auth.default()
except Exception:
    default_project = None

if default_project and "GOOGLE_CLOUD_PROJECT" not in os.environ:
    os.environ["GOOGLE_CLOUD_PROJECT"] = default_project

os.environ.setdefault("GOOGLE_CLOUD_LOCATION", "global")

MODEL = os.getenv("GEMINI_MODEL", "gemini-3.8-flash")

from .agent import root_agent

__all__ = ["root_agent", "MODEL"]
