"""
ARYA AgriDoctor - Compatibility Layer
File: backend/arya_compat.py

Purpose:
- Keep the new backend as the main application.
- Provide the legacy /ai/ask endpoint.
- Reuse the new backend's authentication and AI analysis.
- Avoid creating a separate database.

Run from the repository root:
    uvicorn backend.arya_compat:app --host 0.0.0.0 --port 8000
"""

from typing import Any, Dict, Optional

from fastapi import Header, HTTPException
from pydantic import BaseModel, Field

from backend import main as core


app = core.app


class LegacyAIAskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=20000)
    language: str = Field(default="fa", max_length=20)
    context: Dict[str, Any] = Field(default_factory=dict)
    user_id: Optional[int] = None


@app.post("/ai/ask", tags=["Legacy Compatibility"])
def legacy_ai_ask(
    payload: LegacyAIAskRequest,
    authorization: Optional[str] = Header(default=None),
):
    """
    Compatibility endpoint for older clients.

    Authentication is delegated to the new backend.
    The supplied user_id is never trusted as authentication.
    """

    try:
        user = core.current_user(authorization)
    except HTTPException:
        raise
    except Exception:
        raise HTTPException(
            status_code=401,
            detail="Authentication failed",
        )

    if not isinstance(user, dict) or user.get("id") is None:
        raise HTTPException(
            status_code=401,
            detail="Authenticated user could not be identified",
        )

    authenticated_user_id = user["id"]

    if (
        payload.user_id is not None
        and str(payload.user_id) != str(authenticated_user_id)
    ):
        raise HTTPException(
            status_code=403,
            detail="The requested user does not match the authenticated user",
        )

    request_data = core.AIRequestIn(
        prompt=payload.question,
        language=payload.language,
        context={
            **payload.context,
            "compatibility_layer": True,
            "authenticated_user_id": authenticated_user_id,
        },
    )

    return core.ai_analyze(
        request_data,
        authorization=authorization,
    )


@app.get("/legacy/health", tags=["Legacy Compatibility"])
def legacy_health():
    """
    Basic compatibility health check.
    Does not expose credentials or private configuration.
    """
    return {
        "status": "ok",
        "service": "ARYA AgriDoctor",
        "compatibility_layer": True,
        "main_application": "backend.main:app",
    }
