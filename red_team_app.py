"""
Red Team Attacker App (Demo-safe).

This app launches controlled traffic patterns against the local Blue Team target:
- Normal baseline traffic
- Brute force login attempts
- DDoS-like ping flood
- SQL injection probes
- Port scan probes

Safety: it only allows localhost/127.0.0.1 targets by default.
"""

import asyncio
import os
import random
import time
from typing import Any
from urllib.parse import urlparse

import httpx
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

TARGET_BASE_URL = os.getenv("TARGET_BASE_URL", "http://127.0.0.1:8001")
ATTACKER_ID = os.getenv("ATTACKER_ID", "red-team-01")
NORMAL_TRAFFIC_ID = os.getenv("NORMAL_TRAFFIC_ID", "normal-client-01")
MAX_CONCURRENCY = 25

app = FastAPI(title="AegisAI Red Team", version="1.0.0")

attack_history: list[dict[str, Any]] = []


class AttackRequest(BaseModel):
    target_base_url: str = Field(default=TARGET_BASE_URL)


def assert_safe_target(target_base_url: str) -> None:
    parsed = urlparse(target_base_url)
    host = (parsed.hostname or "").lower()
    allowed_hosts = {"localhost", "127.0.0.1"}
    if host not in allowed_hosts:
        raise HTTPException(
            status_code=400,
            detail="For safety, attacker app only targets localhost/127.0.0.1 in this demo.",
        )


def summarize(name: str, started: float, status_counts: dict[int, int], attempted: int) -> dict[str, Any]:
    summary = {
        "attack": name,
        "attempted": attempted,
        "duration_sec": round(time.time() - started, 2),
        "status_counts": status_counts,
        "timestamp": time.strftime("%H:%M:%S"),
    }
    attack_history.append(summary)
    del attack_history[:-50]
    return summary


async def run_batch(client: httpx.AsyncClient, requests_to_send: list[tuple[str, str, dict[str, Any] | None]]) -> dict[int, int]:
    semaphore = asyncio.Semaphore(MAX_CONCURRENCY)
    counts: dict[int, int] = {}

    async def fire(method: str, url: str, payload: dict[str, Any] | None):
        async with semaphore: # waits for a slot
            try:
                if method == "POST":
                    response = await client.post(url, json=payload)
                else:
                    response = await client.get(url)
                counts[response.status_code] = counts.get(response.status_code, 0) + 1
            except Exception:
                counts[0] = counts.get(0, 0) + 1

    await asyncio.gather(*[fire(method, url, payload) for method, url, payload in requests_to_send])
    return counts


@app.get("/", response_class=HTMLResponse)
async def attacker_ui():
    return """
<!doctype html>
<html>
<head>
  <meta charset=\"utf-8\" />
  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\" />
  <title>Red Team Launcher</title>
  <style>
    body { font-family: 'Space Grotesk', sans-serif; background:#060b16; color:#e2e8f0; margin:0; padding:24px; }
    .wrap { max-width:980px; margin:0 auto; }
    .card { background:#0f172a; border:1px solid #334155; border-radius:14px; padding:18px; margin-bottom:14px; }
    h1 { margin-top:0; }
    .buttons { display:grid; grid-template-columns: repeat(2, minmax(0,1fr)); gap:10px; }
    button { background:linear-gradient(135deg,#7f1d1d,#dc2626); color:#fff; border:none; border-radius:10px; padding:12px; font-weight:700; cursor:pointer; }
    button.safe { background:linear-gradient(135deg,#065f46,#0d9488); }
    input { width:100%; background:#020617; border:1px solid #334155; color:#e2e8f0; border-radius:10px; padding:10px; }
    pre { background:#020617; border:1px solid #334155; border-radius:10px; padding:12px; min-height:120px; overflow:auto; }
  </style>
</head>
<body>
  <div class=\"wrap\">
    <div class=\"card\">
      <h1>Red Team Attack Launcher</h1>
      <p>Fire real HTTP attack traffic against your Blue Team target.</p>
      <label>Target Base URL</label>
      <input id=\"target\" value=\"http://127.0.0.1:8001\" />
            <div class=\"buttons\" style=\"margin-top:12px;\">
                <button class=\"safe\" onclick=\"runAttack('normal')\">Send Normal Traffic</button>
                <button onclick=\"runAttack('brute-force')\">Launch Brute Force</button>
        <button onclick=\"runAttack('ddos')\">Launch DDoS Flood</button>
        <button onclick=\"runAttack('sql-injection')\">Launch SQL Injection</button>
        <button onclick=\"runAttack('port-scan')\">Launch Port Scan</button>
      </div>
      <div class=\"buttons\" style=\"margin-top:10px; grid-template-columns:1fr;\">
        <button class=\"safe\" onclick=\"checkBlocklist()\">Check Blocklist Status</button>
      </div>
    </div>

    <div class=\"card\">
      <h3>Result</h3>
      <pre id=\"out\">Ready.</pre>
    </div>
  </div>

  <script>
    const out = document.getElementById('out');
    async function runAttack(kind) {
      out.textContent = 'Launching ' + kind + '...';
      const target = document.getElementById('target').value.trim();
      const res = await fetch('/attack/' + kind, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_base_url: target })
      });
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }

    async function checkBlocklist() {
      const target = document.getElementById('target').value.trim();
      const res = await fetch('/check-blocklist?target_base_url=' + encodeURIComponent(target));
      const data = await res.json();
      out.textContent = JSON.stringify(data, null, 2);
    }
  </script>
</body>
</html>
    """


@app.get("/history")
async def history():
    return {"items": list(reversed(attack_history))}


@app.get("/check-blocklist")
async def check_blocklist(target_base_url: str = TARGET_BASE_URL):
    assert_safe_target(target_base_url)
    async with httpx.AsyncClient(timeout=20.0) as client:
        resp = await client.get(
            f"{target_base_url}/security/blocklist",
            headers={"x-attacker-id": ATTACKER_ID},
        )
    return resp.json()


@app.post("/attack/brute-force")
async def attack_brute_force(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    requests_to_send = []

    for i in range(500):
        requests_to_send.append(
            (
                "POST",
                f"{req.target_base_url}/target/login",
                {"username": "admin", "password": f"wrong-{i}"},
            )
        )

    async with httpx.AsyncClient(timeout=8.0, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)

    return summarize("brute-force", started, counts, len(requests_to_send))


@app.post("/attack/normal")
async def attack_normal(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()

    # Benign baseline traffic for comparison against active attacks.
    # Keep rate low and use a separate client identity so prior red-team
    # blocks do not taint normal traffic demonstrations.
    requests_to_send: list[tuple[str, str, dict[str, Any] | None]] = []
    for _ in range(10):
        requests_to_send.append(("GET", f"{req.target_base_url}/target/ping", None))

    for i in range(10):
        requests_to_send.append(("GET", f"{req.target_base_url}/target/search?q=dashboard+view+{i}", None))

    for _ in range(4):
        requests_to_send.append(
            (
                "POST",
                f"{req.target_base_url}/target/login",
                {"username": "admin", "password": "aegis-safe-pass"},
            )
        )

    counts: dict[int, int] = {}
    async with httpx.AsyncClient(timeout=8.0, headers={"x-attacker-id": NORMAL_TRAFFIC_ID}) as client:
        # Unblock the normal client id if a previous run happened to flag it.
        try:
            blocklist = await client.get(f"{req.target_base_url}/security/blocklist")
            if blocklist.ok and NORMAL_TRAFFIC_ID in (blocklist.json().get("blocked_sources") or []):
                await client.post(f"{req.target_base_url}/security/unblock/{NORMAL_TRAFFIC_ID}")
        except Exception:
            pass

        # Send requests in a paced manner to emulate legitimate user traffic.
        for method, url, payload in requests_to_send:
            try:
                if method == "POST":
                    response = await client.post(url, json=payload)
                else:
                    response = await client.get(url)
                counts[response.status_code] = counts.get(response.status_code, 0) + 1
            except Exception:
                counts[0] = counts.get(0, 0) + 1

            await asyncio.sleep(0.12)

    return summarize("normal", started, counts, len(requests_to_send))


@app.post("/attack/ddos")
async def attack_ddos(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    requests_to_send = [("GET", f"{req.target_base_url}/target/ping", None) for _ in range(900)]

    async with httpx.AsyncClient(timeout=8.0, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)

    return summarize("ddos", started, counts, len(requests_to_send))


@app.post("/attack/sql-injection")
async def attack_sql_injection(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    payloads = [
        "admin' OR 1=1 --",
        "' UNION SELECT password FROM users --",
        "' OR SLEEP(2) --",
        "' ; DROP TABLE users; --",
    ]
    requests_to_send = []
    for i in range(220):
        q = payloads[i % len(payloads)] + str(random.randint(100, 999))
        requests_to_send.append(("GET", f"{req.target_base_url}/target/search?q={q}", None))

    async with httpx.AsyncClient(timeout=8.0, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)

    return summarize("sql-injection", started, counts, len(requests_to_send))


@app.post("/attack/port-scan")
async def attack_port_scan(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    candidate_ports = list(range(75, 130)) + [443, 8080, 3306, 5432, 6379]
    requests_to_send = [
        ("GET", f"{req.target_base_url}/target/ports/{port}", None) for port in candidate_ports
    ]

    async with httpx.AsyncClient(timeout=8.0, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)

    return summarize("port-scan", started, counts, len(requests_to_send))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
