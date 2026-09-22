"""
main.py

Internal FastAPI microservice orchestrating the AI false-positive filter.
This service has no public ingress: in docker-compose.yml it is deployed
with no `ports:`/`expose:` mapping at all, so it is reachable only via
Docker's internal DNS on `ecdat-net` (e.g. http://ai-service:8000 from
the backend container). Binding to 0.0.0.0 here is what lets other
containers on that private network reach it — it does not, by itself,
expose the service to the host or the internet; that isolation is
enforced entirely at the compose/network layer, not in this file.
"""

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List, Optional

from .chunking import extract_window
from .predictor import predictor

app = FastAPI(title="ECDAT AI Verification Service", version="1.0.0")


class VerifyRequest(BaseModel):
    snippet: str

class VerifyResponse(BaseModel):
    verdict: int               # 0 = False Alarm, 1 = True Threat
    label: str
    confidence: float
    truncated: bool            # True if the snippet was truncated

@app.get("/health")
def health():
    """Satisfies the container healthcheck / Kubernetes readiness probe."""
    return {"status": "ok"}


@app.post("/verify", response_model=VerifyResponse)
def verify(payload: VerifyRequest):
    if not payload.snippet:
        raise HTTPException(status_code=400, detail="snippet must not be empty")

    snippet = payload.snippet
    truncated = False
    if len(snippet) > 1800:
        snippet = snippet[:1800]
        truncated = True

    result = predictor.predict(snippet)

    return VerifyResponse(
        verdict=1,
        label=result["label"],
        confidence=result["confidence"],
        truncated=truncated,
    )
