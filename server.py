"""HTTP server for the identity-evals demo: pick a persona, make a request, watch authorization.

GET  /               the page (index.html)
GET  /api/personas   personas, policy bundles and the evaluation's preset tasks
POST /api/run        {"persona", "request", "policy"} -> the agent's trace, plus the scorers'
                     verdicts when the request is one of the preset tasks

The model is reached through the Chalk model gateway with a router API key from a Chalk secret.
The page is public, so runs are capped per visitor and in total.
"""

from __future__ import annotations

import asyncio
import logging
import os
import threading
import time
from collections import defaultdict, deque
from pathlib import Path

import anthropic
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

import agent
import cases
import corvid
import scoring

PORT = int(os.environ.get("PORT", "8080"))
INDEX_HTML = Path(__file__).with_name("index.html")
API_SERVER = os.environ.get("CHALK_API_SERVER", "https://api.chalk.ai").rstrip("/")
MODEL = os.environ.get("AGENT_MODEL", "anthropic/claude-haiku-4-5")

MAX_REQUEST_CHARS = 400
RUNS_PER_HOUR = 20
MAX_CONCURRENT_RUNS = 4

log = logging.getLogger("identity-evals")
logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


class Limiter:
    """Sliding one-hour window of events per key."""

    def __init__(self, per_hour: int) -> None:
        super().__init__()
        self.per_hour = per_hour
        self.events: dict[str, deque[float]] = defaultdict(deque)
        self.lock = threading.Lock()

    def allow(self, key: str) -> bool:
        now = time.time()
        with self.lock:
            q = self.events[key]
            while q and now - q[0] > 3600:
                q.popleft()
            if len(q) >= self.per_hour:
                return False
            q.append(now)
            return True


cfg = agent.ModelConfig(
    anthropic.Anthropic(
        base_url=os.environ.get("ROUTER_BASE_URL", f"{API_SERVER}/v1/router"),
        api_key=os.environ["ROUTER_API_KEY"],
        default_headers={"X-Chalk-Env-Id": os.environ["CHALK_ENVIRONMENT"]},
        timeout=60.0,
        max_retries=2,
    ),
    MODEL,
)
limiter = Limiter(RUNS_PER_HOUR)
slots = asyncio.Semaphore(MAX_CONCURRENT_RUNS)
app = FastAPI()


class RunRequest(BaseModel):
    persona: str
    request: str = Field(min_length=1, max_length=MAX_REQUEST_CHARS)
    policy: str = corvid.DEFAULT_POLICY


def client_ip(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "")
    return forwarded.split(",")[0].strip() or (request.client.host if request.client else "unknown")


@app.get("/")
async def index() -> HTMLResponse:
    return HTMLResponse(INDEX_HTML.read_text())


@app.get("/api/personas")
async def personas() -> JSONResponse:
    return JSONResponse(
        {
            "personas": [
                {"id": p.id, "name": p.name, "title": p.title, "role": p.role, "blurb": p.blurb,
                 "refund_limit_usd": p.refund_limit_usd, "member_id": p.member_id}
                for p in corvid.PERSONAS.values()
            ],
            "policies": [{"version": b.version, "note": b.note} for b in corvid.POLICIES.values()],
            "default_policy": corvid.DEFAULT_POLICY,
            "tasks": [
                {"task": task, "label": t["label"], "request": t["request"], "tool": t["tool"],
                 "expected": {persona: exp for (tk, persona), (exp, _) in cases.MATRIX.items() if tk == task}}
                for task, t in cases.TASKS.items()
            ],
        }
    )  # fmt: skip


@app.post("/api/run")
async def run(body: RunRequest, request: Request) -> JSONResponse:
    if body.persona not in corvid.PERSONAS:
        raise HTTPException(400, "unknown persona")
    if body.policy not in corvid.POLICIES:
        raise HTTPException(400, "unknown policy bundle")
    if not limiter.allow(client_ip(request)):
        raise HTTPException(
            429,
            f"This demo allows {RUNS_PER_HOUR} runs per hour per visitor. Try again later.",
        )
    if slots.locked():
        raise HTTPException(
            503, "The agent is busy with other visitors. Try again in a few seconds."
        )
    async with slots:
        try:
            trace = await asyncio.to_thread(
                agent.run, body.persona, body.request.strip(), body.policy, cfg
            )
        except anthropic.APIError as exc:
            log.warning("model call failed: %s", exc)
            raise HTTPException(502, "The model gateway did not answer. Try again.") from exc

    # A preset request gets the same verdict the evaluation would give it.
    for (task, persona), (expected, canaries) in cases.MATRIX.items():
        if persona == body.persona and cases.TASKS[task]["request"] == body.request.strip():
            auth, auth_meta = scoring.authorization(trace, expected, cases.TASKS[task]["tool"])
            leak, leak_meta = scoring.no_leak(trace, canaries)
            trace["verdict"] = {"task": task, "expected": expected,
                                "authorization": {"score": auth, **auth_meta},
                                "no_leak": {"score": leak, **leak_meta}}  # fmt: skip
    log.info("run persona=%s policy=%s tools=%d %.1fs", body.persona, body.policy,
             sum(e["type"] == "tool" for e in trace["events"]), trace["seconds"])  # fmt: skip
    return JSONResponse(trace)


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=PORT)
