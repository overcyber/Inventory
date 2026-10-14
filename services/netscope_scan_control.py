"""Redis-backed manual scan dispatch across bridge web and host-network worker.

The web container must never run layer-2 discovery on its bridge network.
The host-network discovery worker owns scans and publishes job status here.
"""
from __future__ import annotations

import json
import os
import time
from uuid import uuid4

import redis

_LOCK = "inventory:netscope:scan:lock"
_QUEUE = "inventory:netscope:scan:queue"
_STATE = "inventory:netscope:scan:state"


def _client():
    url = os.getenv("REDIS_URL", "redis://127.0.0.1:6379/0")
    return redis.Redis.from_url(url, decode_responses=True,
                                socket_connect_timeout=2, socket_timeout=3)


def submit_scan(*, subnet_count: int, auto_snapshot: bool = False):
    client = _client()
    job = {"job_id": uuid4().hex, "auto_snapshot": bool(auto_snapshot),
           "submitted": time.time()}
    if not client.set(_LOCK, job["job_id"], nx=True, ex=3600):
        return False, {"error": "Scan já em andamento",
                       "reason": "already_running"}, 409
    try:
        client.set(_STATE, json.dumps({"status": "scanning",
                   "stage": "queued", "started_at": job["submitted"]}),
                   ex=86400)
        client.lpush(_QUEUE, json.dumps(job))
        return True, {"status": "scanning", "subnets": subnet_count}, 200
    except Exception:
        client.delete(_LOCK)
        raise


def claim_scan():
    raw = _client().rpop(_QUEUE)
    return json.loads(raw) if raw else None


def begin_scan(job):
    _client().set(_STATE, json.dumps({
        "status": "scanning", "stage": "running",
        "started_at": time.time(),
        "job_id": job["job_id"]}), ex=86400)


def finish_scan(job, result=None, error=None):
    client = _client()
    if error is not None:
        payload = {"status": "error", "error": str(error)}
    else:
        payload = {"status": "complete", **(result or {})}
    payload["finished_at"] = time.time()
    client.set(_STATE, json.dumps(payload), ex=86400)
    if client.get(_LOCK) == job["job_id"]:
        client.delete(_LOCK)


def scan_state():
    client = _client()
    raw = client.get(_STATE)
    if not raw:
        return {"status": "idle"}
    state = json.loads(raw)
    if state.get("status") == "scanning":
        age = time.time() - float(state.get("started_at", time.time()))
        if age > 3600:
            return {"status": "error", "error": "Scan expirou; verifique o worker de descoberta"}
    return state
