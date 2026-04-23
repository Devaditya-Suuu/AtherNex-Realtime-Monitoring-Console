import React, { useEffect, useMemo, useRef, useState } from "react";
import { gsap } from "gsap";
import {
  CartesianGrid,
  Legend,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SEVERITY_COLORS = {
  normal: "#18a058",
  warning: "#d69410",
  critical: "#df3f40",
};

const INITIAL_FORM = {
  response_time_ms: 120,
  cpu_usage: 26,
  memory_usage: 38,
  retry_count: 0,
  status_code: 200,
};

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function nowLabel() {
  return new Date().toLocaleTimeString();
}

function mapStatusToSeverity(statusText) {
  if ((statusText || "").includes("HIGH")) return "critical";
  if ((statusText || "").includes("MEDIUM")) return "warning";
  return "normal";
}

function LogsPanel({ logs, logsRef }) {
  return (
    <section className="anim-panel" style={panelStyle}>
      <h3 style={panelTitleStyle}>Live System Logs</h3>
      <div ref={logsRef} style={logsContainerStyle}>
        {logs.map((log) => (
          <div key={log.id} className="log-item" style={logRowStyle}>
            <span style={{ ...logTimestampStyle, color: SEVERITY_COLORS[log.severity] }}>
              [{log.timestamp}]
            </span>
            <span style={{ color: SEVERITY_COLORS[log.severity], fontWeight: 700 }}>
              {log.message}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ResultPanel({ prediction, loading, error, simulating }) {
  const meterRef = useRef(null);

  const statusColor = useMemo(() => {
    if (!prediction?.status) return "#67778a";
    if (prediction.status === "SAFE") return SEVERITY_COLORS.normal;
    if (prediction.status === "MEDIUM RISK") return SEVERITY_COLORS.warning;
    return SEVERITY_COLORS.critical;
  }, [prediction]);

  const score = Math.max(0, Math.min(100, Number(prediction?.risk_score || 0)));

  useEffect(() => {
    if (!meterRef.current) return;

    gsap.to(meterRef.current, {
      width: `${score}%`,
      duration: 0.7,
      ease: "power3.out",
    });
  }, [score]);

  useEffect(() => {
    if (!prediction?.status) return;

    gsap.fromTo(
      ".status-glow",
      { boxShadow: `0 0 0 rgba(0,0,0,0)` },
      {
        boxShadow: `0 0 20px ${statusColor}55`,
        duration: 0.35,
        yoyo: true,
        repeat: 1,
        ease: "power1.out",
      }
    );
  }, [prediction, statusColor]);

  return (
    <section className="anim-panel" style={panelStyle}>
      <h3 style={panelTitleStyle}>Threat Assessment</h3>

      {loading ? <div style={mutedStyle}>Scoring request...</div> : null}
      {simulating ? <div style={mutedStyle}>Running staged attack simulation...</div> : null}
      {error ? <div style={{ ...mutedStyle, color: SEVERITY_COLORS.critical }}>{error}</div> : null}

      <div className="status-glow" style={{ ...resultCardStyle, borderColor: `${statusColor}66` }}>
        <div style={{ ...statusStyle, color: statusColor }}>
          {prediction?.status || "Awaiting prediction"}
        </div>
        <div style={{ fontSize: 13, color: "#465a72", marginTop: 8 }}>
          Action: <strong>{prediction?.action || "-"}</strong>
        </div>
        <div style={{ fontSize: 13, color: "#465a72", marginTop: 2 }}>
          Confidence: {typeof prediction?.confidence === "number" ? `${(prediction.confidence * 100).toFixed(1)}%` : "-"}
        </div>
        <div style={{ marginTop: 12 }}>
          <div style={{ fontSize: 13, color: "#465a72" }}>Risk Score: {score.toFixed(1)}/100</div>
          <div style={meterOuterStyle}>
            <div
              ref={meterRef}
              style={{
                ...meterInnerStyle,
                width: "0%",
                background: "linear-gradient(90deg, #18a058, #d69410, #df3f40)",
              }}
            />
          </div>
        </div>
      </div>
    </section>
  );
}

function ChartsPanel({ riskHistory, metricsHistory }) {
  return (
    <section className="anim-panel" style={panelStyle}>
      <h3 style={panelTitleStyle}>Risk Score Over Time</h3>
      <div style={{ width: "100%", height: 220 }}>
        <ResponsiveContainer>
          <LineChart data={riskHistory}>
            <CartesianGrid strokeDasharray="3 3" stroke="#dce4ef" />
            <XAxis dataKey="time" stroke="#9bb0d1" />
            <YAxis domain={[0, 100]} stroke="#9bb0d1" />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
              labelStyle={{ color: "#cbd5e1" }}
              itemStyle={{ color: "#e2e8f0" }}
            />
            <Line type="monotone" dataKey="risk" stroke="#00a39a" strokeWidth={2.4} dot={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <h3 style={{ ...panelTitleStyle, marginTop: 12 }}>System Metrics</h3>
      <div style={{ width: "100%", height: 220 }}>
        <ResponsiveContainer>
          <LineChart data={metricsHistory}>
            <CartesianGrid strokeDasharray="3 3" stroke="#dce4ef" />
            <XAxis dataKey="time" stroke="#9bb0d1" />
            <YAxis domain={[0, 100]} stroke="#9bb0d1" />
            <Tooltip
              contentStyle={{ background: "#0f172a", border: "1px solid #334155", borderRadius: 8 }}
              labelStyle={{ color: "#cbd5e1" }}
              itemStyle={{ color: "#e2e8f0" }}
            />
            <Legend wrapperStyle={{ color: "#e2e8f0" }} />
            <Line type="monotone" dataKey="cpu" stroke="#3478f6" strokeWidth={2.2} dot={false} name="CPU %" />
            <Line type="monotone" dataKey="memory" stroke="#8d36f0" strokeWidth={2.2} dot={false} name="Memory %" />
          </LineChart>
        </ResponsiveContainer>
      </div>
    </section>
  );
}

function StatCards({ prediction, logs }) {
  const criticalCount = logs.filter((l) => l.severity === "critical").length;
  const warningCount = logs.filter((l) => l.severity === "warning").length;

  return (
    <div className="anim-panel" style={statsGridStyle}>
      <div style={statCardStyle}>
        <div style={statLabelStyle}>Current Status</div>
        <div style={statValueStyle}>{prediction?.status || "IDLE"}</div>
      </div>
      <div style={statCardStyle}>
        <div style={statLabelStyle}>Critical Events</div>
        <div style={{ ...statValueStyle, color: SEVERITY_COLORS.critical }}>{criticalCount}</div>
      </div>
      <div style={statCardStyle}>
        <div style={statLabelStyle}>Warning Events</div>
        <div style={{ ...statValueStyle, color: SEVERITY_COLORS.warning }}>{warningCount}</div>
      </div>
    </div>
  );
}

export default function CyberMonitoringDashboard({ apiBaseUrl = "http://localhost:8001" }) {
  const rootRef = useRef(null);
  const logsRef = useRef(null);
  const pulseRef = useRef(null);

  const [formData, setFormData] = useState(INITIAL_FORM);
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState("");
  const [logs, setLogs] = useState(() => [
    { id: Date.now(), timestamp: nowLabel(), message: "Security console online", severity: "normal" },
  ]);
  const [riskHistory, setRiskHistory] = useState([]);
  const [metricsHistory, setMetricsHistory] = useState([]);

  const addLog = (message, severity = "normal") => {
    setLogs((prev) => {
      const next = [
        ...prev,
        { id: Date.now() + Math.random(), timestamp: nowLabel(), message, severity },
      ];
      return next.slice(-140);
    });
  };

  useEffect(() => {
    // Entry animation for main dashboard sections.
    const ctx = gsap.context(() => {
      gsap.from(".anim-hero", {
        y: -18,
        opacity: 0,
        duration: 0.65,
        ease: "power3.out",
      });

      gsap.from(".anim-panel", {
        y: 16,
        opacity: 0,
        stagger: 0.08,
        duration: 0.65,
        delay: 0.08,
        ease: "power2.out",
      });

      if (pulseRef.current) {
        gsap.to(pulseRef.current, {
          scale: 1.22,
          opacity: 0.5,
          repeat: -1,
          yoyo: true,
          duration: 0.9,
          ease: "sine.inOut",
        });
      }
    }, rootRef);

    return () => ctx.revert();
  }, []);

  // Auto-scroll log feed and animate newest row.
  useEffect(() => {
    if (logsRef.current) {
      logsRef.current.scrollTop = logsRef.current.scrollHeight;
      const last = logsRef.current.querySelector(".log-item:last-child");
      if (last) {
        gsap.fromTo(last, { x: -10, opacity: 0 }, { x: 0, opacity: 1, duration: 0.28, ease: "power1.out" });
      }
    }
  }, [logs]);

  // Real-time autonomous system log stream.
  useEffect(() => {
    const pool = [
      { message: "Normal API request", severity: "normal" },
      { message: "Session token validated", severity: "normal" },
      { message: "CPU usage spike detected", severity: "warning" },
      { message: "Memory pressure increasing", severity: "warning" },
      { message: "Multiple failed login attempts", severity: "critical" },
      { message: "Unusual retry burst detected", severity: "critical" },
    ];

    const timer = setInterval(() => {
      if (simulating) return;
      const item = pool[Math.floor(Math.random() * pool.length)];
      addLog(item.message, item.severity);
    }, 2500);

    return () => clearInterval(timer);
  }, [simulating]);

  const onInputChange = (event) => {
    const { name, value } = event.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const appendCharts = (payload, result) => {
    const pointTime = nowLabel();
    setRiskHistory((prev) => [...prev.slice(-39), { time: pointTime, risk: Number(result.risk_score || 0) }]);
    setMetricsHistory((prev) => [
      ...prev.slice(-39),
      {
        time: pointTime,
        cpu: Number(payload.cpu_usage || 0),
        memory: Number(payload.memory_usage || 0),
      },
    ]);
  };

  const callPredict = async (payload) => {
    const response = await fetch(`${apiBaseUrl}/predict`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload),
    });

    const body = await response.json();
    if (!response.ok) {
      throw new Error(body?.detail || "Prediction failed");
    }

    return body;
  };

  const runPrediction = async (payload, sourceLabel = "Manual prediction") => {
    setLoading(true);
    setError("");

    try {
      const result = await callPredict(payload);
      setPrediction(result);
      appendCharts(payload, result);

      const severity = mapStatusToSeverity(result.status);
      addLog(`${sourceLabel} -> ${result.status} (${result.action})`, severity);
      return result;
    } catch (err) {
      const message = err.message || "Unable to reach backend";
      setError(message);
      addLog(`Prediction error: ${message}`, "critical");
      throw err;
    } finally {
      setLoading(false);
    }
  };

  const handleRunPrediction = async (event) => {
    event.preventDefault();

    const payload = {
      response_time_ms: Number(formData.response_time_ms),
      cpu_usage: Number(formData.cpu_usage),
      memory_usage: Number(formData.memory_usage),
      retry_count: Number(formData.retry_count),
      status_code: Number(formData.status_code),
      message: "manual dashboard prediction",
    };

    await runPrediction(payload);
  };

  const runAttackSimulation = async () => {
    if (simulating || loading) return;

    setSimulating(true);
    setError("");

    try {
      addLog("Simulation started: baseline traffic", "normal");
      await sleep(1000);

      addLog("Step 1: Normal API traffic stabilized", "normal");
      await sleep(1000);

      addLog("Step 2: CPU usage spike detected", "warning");
      setFormData((prev) => ({ ...prev, cpu_usage: 88, memory_usage: 72 }));
      await sleep(1100);

      addLog("Step 3: Retry count surge detected", "critical");
      setFormData((prev) => ({ ...prev, retry_count: 14, status_code: 503, response_time_ms: 4500 }));
      await sleep(1100);

      const maliciousPayload = {
        response_time_ms: 5000,
        cpu_usage: 95,
        memory_usage: 98,
        retry_count: 15,
        status_code: 503,
        message: "multiple failed login attempts and suspicious retries",
      };

      addLog("Step 4: Executing backend threat prediction", "critical");
      const result = await runPrediction(maliciousPayload, "Simulation");

      if (result.status === "HIGH RISK") {
        addLog("Step 5: Threat confirmed -> BLOCK IP", "critical");
      } else {
        addLog("Step 5: Elevated but non-critical response", "warning");
      }
    } catch (_err) {
      // Errors are handled by runPrediction.
    } finally {
      setSimulating(false);
    }
  };

  return (
    <div
      ref={rootRef}
      style={{
        ...rootStyle,
        background:
          "radial-gradient(circle at 10% 0%, #102a43 0%, transparent 30%), radial-gradient(circle at 90% 80%, #2d1b52 0%, transparent 26%), linear-gradient(180deg, #020617 0%, #0b1220 100%)",
      }}
    >
      <div className="anim-hero" style={heroStyle}>
        <div>
          <h2 style={{ margin: 0 }}>AtherNex Realtime Monitoring Console</h2>
          <p style={{ marginTop: 6, marginBottom: 0, color: "#516173" }}>
            Live anomaly detection with backend-driven predictions, timeline logs, and telemetry charts.
          </p>
        </div>
        <div style={liveBadgeStyle}>
          <span ref={pulseRef} style={pulseDotStyle} />
          LIVE
        </div>
      </div>

      <StatCards prediction={prediction} logs={logs} />

      <div style={gridStyle}>
        <section className="anim-panel" style={panelStyle}>
          <h3 style={panelTitleStyle}>Input Signals</h3>
          <form onSubmit={handleRunPrediction} style={{ display: "grid", gap: 10 }}>
            <InputRow label="Response Time (ms)" name="response_time_ms" value={formData.response_time_ms} onChange={onInputChange} />
            <InputRow label="CPU Usage (%)" name="cpu_usage" value={formData.cpu_usage} onChange={onInputChange} />
            <InputRow label="Memory Usage (%)" name="memory_usage" value={formData.memory_usage} onChange={onInputChange} />
            <InputRow label="Retry Count" name="retry_count" value={formData.retry_count} onChange={onInputChange} />
            <InputRow label="Status Code" name="status_code" value={formData.status_code} onChange={onInputChange} />

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 8, marginTop: 6 }}>
              <button style={primaryButtonStyle} type="submit" disabled={loading || simulating}>
                {loading ? "Running..." : "Run Prediction"}
              </button>
              <button style={secondaryButtonStyle} type="button" onClick={runAttackSimulation} disabled={loading || simulating}>
                {simulating ? "Simulating..." : "Simulate Attack"}
              </button>
            </div>
          </form>
        </section>

        <ResultPanel prediction={prediction} loading={loading} error={error} simulating={simulating} />
      </div>

      <div style={gridStyle}>
        <LogsPanel logs={logs} logsRef={logsRef} />
        <ChartsPanel riskHistory={riskHistory} metricsHistory={metricsHistory} />
      </div>
    </div>
  );
}

function InputRow({ label, name, value, onChange }) {
  return (
    <label style={inputRowStyle}>
      <span style={inputLabelStyle}>{label}</span>
      <input type="number" name={name} value={value} onChange={onChange} style={inputStyle} />
    </label>
  );
}

const rootStyle = {
  fontFamily: "Space Grotesk, sans-serif",
  color: "#e2e8f0",
  maxWidth: 1280,
  margin: "0 auto",
  padding: 20,
  borderRadius: 18,
};

const heroStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: 12,
  gap: 12,
};

const liveBadgeStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  fontWeight: 800,
  color: "#e2e8f0",
  borderRadius: 999,
  border: "1px solid rgba(148,163,184,0.26)",
  padding: "8px 12px",
  background: "rgba(15,23,42,0.92)",
  boxShadow: "0 7px 18px rgba(0,0,0,0.35)",
};

const pulseDotStyle = {
  width: 9,
  height: 9,
  borderRadius: "50%",
  background: "#18a058",
  display: "inline-block",
};

const statsGridStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(3, minmax(0, 1fr))",
  gap: 10,
  marginBottom: 14,
};

const statCardStyle = {
  borderRadius: 12,
  border: "1px solid rgba(148,163,184,0.2)",
  background: "rgba(15,23,42,0.86)",
  padding: 12,
};

const statLabelStyle = {
  fontSize: 12,
  color: "#94a3b8",
};

const statValueStyle = {
  marginTop: 4,
  fontWeight: 800,
  fontSize: 19,
};

const gridStyle = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 14,
  marginBottom: 14,
};

const panelStyle = {
  borderRadius: 16,
  border: "1px solid rgba(148,163,184,0.2)",
  background: "rgba(15,23,42,0.88)",
  padding: 14,
  minHeight: 250,
  boxShadow: "0 14px 32px rgba(0,0,0,0.35)",
};

const resultCardStyle = {
  borderRadius: 12,
  border: "1px solid rgba(148,163,184,0.22)",
  background: "rgba(2,6,23,0.9)",
  padding: 12,
  marginTop: 8,
};

const panelTitleStyle = {
  marginTop: 0,
  marginBottom: 10,
  fontSize: 16,
  letterSpacing: 0.2,
};

const inputRowStyle = {
  display: "grid",
  gap: 4,
};

const inputLabelStyle = {
  fontSize: 13,
  color: "#9bb0d1",
};

const inputStyle = {
  borderRadius: 10,
  border: "1px solid rgba(148,163,184,0.24)",
  background: "#0f172a",
  color: "#e2e8f0",
  padding: "8px 10px",
  fontSize: 14,
};

const primaryButtonStyle = {
  border: 0,
  borderRadius: 10,
  padding: "10px 12px",
  cursor: "pointer",
  color: "#ffffff",
  background: "linear-gradient(135deg, #00a39a, #00c06f)",
  fontWeight: 700,
};

const secondaryButtonStyle = {
  borderRadius: 10,
  border: "1px solid rgba(56,107,161,0.24)",
  padding: "10px 12px",
  cursor: "pointer",
  color: "#dbeafe",
  background: "#0b2447",
  fontWeight: 700,
};

const logsContainerStyle = {
  height: 450,
  overflowY: "auto",
  border: "1px solid rgba(148,163,184,0.2)",
  borderRadius: 12,
  padding: 10,
  background: "#020617",
};

const logRowStyle = {
  display: "flex",
  gap: 8,
  fontSize: 13,
  marginBottom: 7,
  alignItems: "baseline",
};

const logTimestampStyle = {
  fontFamily: "JetBrains Mono, monospace",
  minWidth: 84,
};

const mutedStyle = {
  fontSize: 13,
  color: "#94a3b8",
};

const statusStyle = {
  fontSize: 22,
  fontWeight: 800,
};

const meterOuterStyle = {
  marginTop: 6,
  height: 10,
  borderRadius: 999,
  background: "#1e293b",
  overflow: "hidden",
};

const meterInnerStyle = {
  height: "100%",
};
