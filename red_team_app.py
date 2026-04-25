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
BROWSER_NORMAL_ID = "normal-browser-client"
MAX_CONCURRENCY = 25
# Large batches (brute 500, DDoS 900) need a generous timeout so runs finish reliably.
HTTPX_TIMEOUT = 60.0

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
    .toggle { margin-top:12px; display:flex; align-items:center; gap:8px; color:#cbd5e1; font-size:13px; }
    .range-wrap { margin-top:10px; display:grid; gap:6px; color:#cbd5e1; }
    .range-row { display:flex; align-items:center; gap:10px; }
    .range-row input[type=range] { flex:1; }
    .range-value { min-width:92px; text-align:right; font-weight:700; color:#f8fafc; }
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
      <label class=\"toggle\">
        <input id=\"clientBurst\" type=\"checkbox\" style=\"width:auto;\" />
        Browser Burst Mode (show every request in DevTools network tab)
      </label>
      <div class=\"range-wrap\">
        <label>Burst Intensity</label>
        <div class=\"range-row\">
          <input id=\"burstIntensity\" type=\"range\" min=\"1\" max=\"5\" step=\"1\" value=\"3\" />
          <span id=\"burstLabel\" class=\"range-value\">Level 3</span>
        </div>
      </div>
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
      <h2 style=\"margin-top:0;\">Insider Threat Scenarios</h2>
      <div class=\"buttons\">
        <button onclick=\"runAttack('insider-after-hours')\">👤 After Hours Intrusion</button>
        <button onclick=\"runAttack('insider-privilege-escalation')\">📈 Privilege Escalation</button>
        <button onclick=\"runAttack('insider-mass-exfiltration')\">💾 Mass Data Exfiltration</button>
      </div>
    </div>

    <div class=\"card\">
      <h3>Result</h3>
      <pre id=\"out\">Ready.</pre>
    </div>
  </div>

  <script>
    const out = document.getElementById('out');
    const intensityInput = document.getElementById('burstIntensity');
    const intensityLabel = document.getElementById('burstLabel');
    const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));
    const burstHeaders = {
      'x-attacker-id': 'red-team-browser',
      'Content-Type': 'application/json'
    };
    const BROWSER_NORMAL_ID = 'normal-browser-client';

    function isSafeTarget(url) {
      try {
        const parsed = new URL(url);
        const host = (parsed.hostname || '').toLowerCase();
        return host === 'localhost' || host === '127.0.0.1';
      } catch (_e) {
        return false;
      }
    }

    async function ensureNormalBrowserUnblocked(target) {
      try {
        const bl = await fetch(`${target}/security/blocklist`);
        if (!bl.ok) return;
        const data = await bl.json();
        const blocked = data.blocked_sources || [];
        if (blocked.includes(BROWSER_NORMAL_ID)) {
          await fetch(`${target}/security/unblock/${encodeURIComponent(BROWSER_NORMAL_ID)}`, { method: 'POST' });
        }
      } catch (_e) {
        /* ignore */
      }
    }
    const intensityMap = {
      1: { ddos: 160, brute: 90, sqli: 70, ports: 35, wave: 24, insiderDownload: 80, normalPing: 8, normalSearch: 5 },
      2: { ddos: 350, brute: 180, sqli: 120, ports: 60, wave: 40, insiderDownload: 200, normalPing: 12, normalSearch: 8 },
      3: { ddos: 700, brute: 320, sqli: 220, ports: 95, wave: 70, insiderDownload: 400, normalPing: 16, normalSearch: 10 },
      4: { ddos: 1100, brute: 520, sqli: 340, ports: 120, wave: 100, insiderDownload: 700, normalPing: 20, normalSearch: 14 },
      5: { ddos: 1600, brute: 760, sqli: 520, ports: 150, wave: 140, insiderDownload: 1000, normalPing: 26, normalSearch: 18 }
    };

    function selectedIntensity() {
      const level = Number(intensityInput?.value || 3);
      return intensityMap[level] || intensityMap[3];
    }

    function updateIntensityLabel() {
      const level = Number(intensityInput?.value || 3);
      const profile = intensityMap[level] || intensityMap[3];
      intensityLabel.textContent = `Level ${level} (${profile.ddos} DDoS req)`;
    }

    if (intensityInput) {
      intensityInput.addEventListener('input', updateIntensityLabel);
      updateIntensityLabel();
    }

    async function sendInWaves(requests, waveSize = 60) {
      const counts = {};
      let failed = 0;

      for (let i = 0; i < requests.length; i += waveSize) {
        const wave = requests.slice(i, i + waveSize);
        const results = await Promise.allSettled(
          wave.map((req) => fetch(req.url, req.options))
        );
        for (const result of results) {
          if (result.status === 'fulfilled') {
            const code = result.value.status;
            counts[code] = (counts[code] || 0) + 1;
          } else {
            failed += 1;
          }
        }
      }

      if (failed > 0) counts[0] = failed;
      return counts;
    }

    async function runBrowserAttack(kind, target) {
      if (!target) throw new Error('Target URL is required');
      if (!isSafeTarget(target)) {
        throw new Error('Browser burst only allows http://localhost or http://127.0.0.1 targets for demo safety');
      }
      const started = performance.now();
      const requests = [];
      const profile = selectedIntensity();

      if (kind === 'ddos') {
        for (let i = 0; i < profile.ddos; i++) {
          requests.push({ url: `${target}/target/ping`, options: { method: 'GET', headers: burstHeaders } });
        }
      } else if (kind === 'brute-force') {
        for (let i = 0; i < profile.brute; i++) {
          requests.push({
            url: `${target}/target/login`,
            options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'admin', password: `wrong-${i}` }) }
          });
        }
      } else if (kind === 'sql-injection') {
        const payloads = [
          "admin' OR 1=1 --",
          "' UNION SELECT password FROM users --",
          "' OR SLEEP(2) --",
          "' ; DROP TABLE users; --"
        ];
        for (let i = 0; i < profile.sqli; i++) {
          const q = encodeURIComponent(payloads[i % payloads.length] + String(100 + i));
          requests.push({ url: `${target}/target/search?q=${q}`, options: { method: 'GET', headers: burstHeaders } });
        }
      } else if (kind === 'port-scan') {
        const basePorts = Array.from({ length: profile.ports }, (_, i) => i + 75);
        const extraPorts = [443, 8080, 3306, 5432, 6379];
        const ports = [...new Set([...basePorts, ...extraPorts])];
        for (const port of ports) {
          requests.push({ url: `${target}/target/ports/${port}`, options: { method: 'GET', headers: burstHeaders } });
        }
      } else if (kind === 'normal') {
        await ensureNormalBrowserUnblocked(target);
        for (let i = 0; i < profile.normalPing; i++) requests.push({ url: `${target}/target/ping`, options: { method: 'GET', headers: { 'x-attacker-id': BROWSER_NORMAL_ID } } });
        for (let i = 0; i < profile.normalSearch; i++) requests.push({ url: `${target}/target/search?q=dashboard+view+${i}`, options: { method: 'GET', headers: { 'x-attacker-id': BROWSER_NORMAL_ID } } });
        for (let i = 0; i < 4; i++) {
          requests.push({
            url: `${target}/target/login`,
            options: { method: 'POST', headers: { 'x-attacker-id': BROWSER_NORMAL_ID, 'Content-Type': 'application/json' }, body: JSON.stringify({ username: 'admin', password: 'aegis-safe-pass' }) }
          });
        }
      } else if (kind === 'insider-after-hours') {
        const sequence = [
          { url: `${target}/internal/login`, options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'alice', location: 'Moscow', hour: 2 }) } },
          { url: `${target}/internal/access`, options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'alice', department: 'finance' }) } },
          { url: `${target}/internal/download`, options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'alice', department: 'finance', file_count: 500 }) } }
        ];
        const counts = {};
        for (const req of sequence) {
          try {
            const response = await fetch(req.url, req.options);
            counts[response.status] = (counts[response.status] || 0) + 1;
          } catch (_e) {
            counts[0] = (counts[0] || 0) + 1;
          }
          await sleep(500);
        }
        return {
          attack: kind,
          mode: 'browser-burst',
          attempted: sequence.length,
          duration_sec: Number(((performance.now() - started) / 1000).toFixed(2)),
          status_counts: counts,
          timestamp: new Date().toLocaleTimeString()
        };
      } else if (kind === 'insider-privilege-escalation') {
        const departments = ['hr', 'finance', 'executive', 'legal'];
        for (const dept of departments) {
          requests.push({
            url: `${target}/internal/access`,
            options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'bob', department: dept }) }
          });
        }
        requests.push({
          url: `${target}/internal/download`,
          options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'bob', department: 'executive', file_count: 200 }) }
        });
      } else if (kind === 'insider-mass-exfiltration') {
        const sequence = [
          { url: `${target}/internal/login`, options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'carol', location: 'Delhi', hour: 3 }) } },
          { url: `${target}/internal/download`, options: { method: 'POST', headers: burstHeaders, body: JSON.stringify({ username: 'carol', department: 'finance', file_count: profile.insiderDownload }) } }
        ];
        const counts = {};
        for (const req of sequence) {
          try {
            const response = await fetch(req.url, req.options);
            counts[response.status] = (counts[response.status] || 0) + 1;
          } catch (_e) {
            counts[0] = (counts[0] || 0) + 1;
          }
        }
        return {
          attack: kind,
          mode: 'browser-burst',
          attempted: sequence.length,
          duration_sec: Number(((performance.now() - started) / 1000).toFixed(2)),
          status_counts: counts,
          timestamp: new Date().toLocaleTimeString()
        };
      }

      const counts = await sendInWaves(requests, kind === 'ddos' ? profile.wave : Math.max(24, Math.floor(profile.wave * 0.6)));
      return {
        attack: kind,
        mode: 'browser-burst',
        intensity_level: Number(intensityInput?.value || 3),
        attempted: requests.length,
        duration_sec: Number(((performance.now() - started) / 1000).toFixed(2)),
        status_counts: counts,
        timestamp: new Date().toLocaleTimeString()
      };
    }

    async function runAttack(kind) {
      out.textContent = 'Launching ' + kind + '...';
      const target = document.getElementById('target').value.trim();
      const browserBurst = document.getElementById('clientBurst').checked;

      if (browserBurst) {
        try {
          const data = await runBrowserAttack(kind, target);
          out.textContent = JSON.stringify(data, null, 2);
        } catch (err) {
          out.textContent = JSON.stringify({ error: err.message || 'Browser burst failed' }, null, 2);
        }
        return;
      }

      const res = await fetch('/attack/' + kind, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_base_url: target })
      });
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (_e) {
        data = { error: 'Invalid JSON from server', status: res.status, body: text.slice(0, 500) };
      }
      if (!res.ok) {
        data = { ...data, http_status: res.status, ok: false };
      }
      out.textContent = JSON.stringify(data, null, 2);
    }

    async function checkBlocklist() {
      const target = document.getElementById('target').value.trim();
      const res = await fetch('/check-blocklist?target_base_url=' + encodeURIComponent(target));
      const text = await res.text();
      let data;
      try {
        data = JSON.parse(text);
      } catch (_e) {
        data = { error: 'Invalid JSON from server', status: res.status, body: text.slice(0, 500) };
      }
      if (!res.ok) {
        data = { ...data, http_status: res.status, ok: false };
      }
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
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT) as client:
        resp = await client.get(
            f"{target_base_url}/security/blocklist",
            headers={"x-attacker-id": ATTACKER_ID},
        )
    return resp.json()


@app.post("/attack/insider-after-hours")
async def attack_insider_after_hours(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    counts: dict[int, int] = {}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
        try:
            login = await client.post(
                f"{req.target_base_url}/internal/login",
                json={"username": "alice", "location": "Moscow", "hour": 2},
            )
            counts[login.status_code] = counts.get(login.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1
        await asyncio.sleep(0.5)

        try:
            access = await client.post(
                f"{req.target_base_url}/internal/access",
                json={"username": "alice", "department": "finance"},
            )
            counts[access.status_code] = counts.get(access.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1
        await asyncio.sleep(0.5)

        try:
            download = await client.post(
                f"{req.target_base_url}/internal/download",
                json={"username": "alice", "department": "finance", "file_count": 500},
            )
            counts[download.status_code] = counts.get(download.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1

    return summarize("insider-after-hours", started, counts, 3)


@app.post("/attack/insider-privilege-escalation")
async def attack_insider_privilege_escalation(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    departments = ["hr", "finance", "executive", "legal"]
    requests_to_send = [
        (
            "POST",
            f"{req.target_base_url}/internal/access",
            {"username": "bob", "department": dept},
        )
        for dept in departments
    ]

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)
        try:
            download = await client.post(
                f"{req.target_base_url}/internal/download",
                json={"username": "bob", "department": "executive", "file_count": 200},
            )
            counts[download.status_code] = counts.get(download.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1

    return summarize("insider-privilege-escalation", started, counts, 5)


@app.post("/attack/insider-mass-exfiltration")
async def attack_insider_mass_exfiltration(req: AttackRequest):
    assert_safe_target(req.target_base_url)
    started = time.time()
    counts: dict[int, int] = {}

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
        try:
            login = await client.post(
                f"{req.target_base_url}/internal/login",
                json={"username": "carol", "location": "Delhi", "hour": 3},
            )
            counts[login.status_code] = counts.get(login.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1

        try:
            download = await client.post(
                f"{req.target_base_url}/internal/download",
                json={"username": "carol", "department": "finance", "file_count": 1000},
            )
            counts[download.status_code] = counts.get(download.status_code, 0) + 1
        except Exception:
            counts[0] = counts.get(0, 0) + 1

    return summarize("insider-mass-exfiltration", started, counts, 2)


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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
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
    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": NORMAL_TRAFFIC_ID}) as client:
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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
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

    async with httpx.AsyncClient(timeout=HTTPX_TIMEOUT, headers={"x-attacker-id": ATTACKER_ID}) as client:
        counts = await run_batch(client, requests_to_send)

    return summarize("port-scan", started, counts, len(requests_to_send))


if __name__ == "__main__":
    import uvicorn

    uvicorn.run(app, host="0.0.0.0", port=8002, log_level="info")
