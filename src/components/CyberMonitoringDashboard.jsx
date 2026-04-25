import React, { useEffect, useMemo, useRef, useState } from "react";
import { gsap } from "gsap";
import { io } from "socket.io-client";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";

const SEVERITY_COLORS = {
  normal: "#20c997",
  warning: "#f59e0b",
  critical: "#ef4444",
};

const SCENARIOS = {
  normal: {
    label: "Normal Traffic",
    tone: "normal",
    description: "Baseline web/API traffic with stable system metrics.",
    steps: [
      "Normal API requests observed",
      "Authentication requests within normal range",
      "No anomalies detected by sensor mesh",
    ],
    series: [12, 14, 18, 21, 17],
    payload: {
      response_time_ms: 120,
      cpu_usage: 22,
      memory_usage: 35,
      retry_count: 0,
      status_code: 200,
      message: "normal traffic and healthy auth patterns",
    },
  },
  bruteForce: {
    label: "Brute Force",
    tone: "critical",
    description: "Repeated login failures and rapid retries from a single source.",
    steps: [
      "Normal traffic begins",
      "Failed login attempts increase",
      "Retry burst detected from same IP",
      "Authentication source flagged for blocking",
    ],
    series: [12, 28, 45, 78, 91],
    payload: {
      response_time_ms: 3200,
      cpu_usage: 78,
      memory_usage: 64,
      retry_count: 19,
      status_code: 401,
      message: "multiple failed login attempts and rapid retries",
    },
  },
  ddos: {
    label: "DDoS",
    tone: "critical",
    description: "Volumetric request flood causing resource pressure and latency spikes.",
    steps: [
      "Internet node receives unusual burst",
      "Firewall rate limiting engaged",
      "Server latency spikes across clusters",
      "Traffic source quarantined",
    ],
    series: [18, 36, 63, 84, 96],
    payload: {
      response_time_ms: 5400,
      cpu_usage: 96,
      memory_usage: 92,
      retry_count: 5,
      status_code: 503,
      message: "volumetric traffic flood consistent with DDoS",
    },
  },
  sqlInjection: {
    label: "SQL Injection",
    tone: "warning",
    description: "Suspicious payloads probing input fields and database endpoints.",
    steps: [
      "Unusual parameter strings observed",
      "WAF pattern match fired",
      "Database query anomalies detected",
      "Malicious payload blocked",
    ],
    series: [14, 30, 52, 69, 86],
    payload: {
      response_time_ms: 1900,
      cpu_usage: 66,
      memory_usage: 58,
      retry_count: 8,
      status_code: 403,
      message: "payload contains SQL injection markers and probes",
    },
  },
  insiderThreat: {
    label: "Insider Threat",
    tone: "critical",
    description: "Authenticated user access with abnormal access patterns and retries.",
    steps: [
      "Trusted session active",
      "Access pattern diverges from baseline",
      "Multiple high-risk actions triggered",
      "Session terminated and source blocked",
    ],
    series: [16, 29, 43, 71, 89],
    payload: {
      response_time_ms: 2200,
      cpu_usage: 71,
      memory_usage: 67,
      retry_count: 12,
      status_code: 500,
      message: "trusted user with abnormal access pattern",
    },
  },
};

const NETWORK_NODES = [
  { id: "internet", label: "Internet", x: 12, y: 50 },
  { id: "firewall", label: "Firewall", x: 34, y: 50 },
  { id: "server1", label: "Server 1", x: 58, y: 30 },
  { id: "server2", label: "Server 2", x: 58, y: 70 },
  { id: "database", label: "Database", x: 82, y: 50 },
];

const NETWORK_EDGES = [
  ["internet", "firewall"],
  ["firewall", "server1"],
  ["firewall", "server2"],
  ["server1", "database"],
  ["server2", "database"],
];

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

function nowLabel() {
  return new Date().toLocaleTimeString();
}

function createInitialMetrics() {
  return {
    response_time_ms: 120,
    cpu_usage: 22,
    memory_usage: 35,
    retry_count: 0,
    status_code: 200,
    activeScenario: "normal",
  };
}

function severityFromStatus(statusText) {
  if ((statusText || "").includes("HIGH")) return "critical";
  if ((statusText || "").includes("MEDIUM")) return "warning";
  return "normal";
}

function clamp(n, min, max) {
  return Math.max(min, Math.min(max, n));
}

function getRouteForScenario(key) {
  if (key === "ddos") return ["internet", "firewall", "server1", "database"];
  if (key === "sqlInjection") return ["internet", "firewall", "server2", "database"];
  if (key === "insiderThreat") return ["server2", "database"];
  if (key === "bruteForce") return ["internet", "firewall", "server1"];
  return ["internet", "firewall", "server1"];
}

function routeToEdges(route) {
  return route.slice(0, -1).map((from, index) => ({
    from,
    to: route[index + 1],
  }));
}

function getNodePosition(id) {
  return NETWORK_NODES.find((node) => node.id === id) || NETWORK_NODES[0];
}

function routeForPath(path = "") {
  if (path.includes("/internal/")) return getRouteForScenario("insiderThreat");
  if (path.includes("/target/login")) return getRouteForScenario("bruteForce");
  if (path.includes("/target/search")) return getRouteForScenario("sqlInjection");
  if (path.includes("/target/ports")) return getRouteForScenario("insiderThreat");
  if (path.includes("/target/ping")) return getRouteForScenario("ddos");
  return getRouteForScenario("normal");
}

function scenarioFromPath(path = "") {
  if (path.includes("/internal/")) return "insiderThreat";
  if (path.includes("/target/login")) return "bruteForce";
  if (path.includes("/target/search")) return "sqlInjection";
  if (path.includes("/target/ports")) return "insiderThreat";
  if (path.includes("/target/ping")) return "ddos";
  return "normal";
}

function assessmentFromSecurityEvent(event) {
  if (!event) return null;

  if (event.event_type === "traffic") {
    return {
      status: event.status || "SAFE",
      action: event.action || "MONITOR",
      risk_score: Number(event.risk_score || 0),
      confidence: 1,
      scenario: scenarioFromPath(event.path || ""),
      route: routeForPath(event.path || ""),
    };
  }

  if (event.event_type === "auto_block") {
    return {
      status: "HIGH RISK",
      action: "BLOCK IP",
      risk_score: Number(event.risk_score || 100),
      confidence: 1,
      scenario: scenarioFromPath(event.path || "/target/login"),
      route: routeForPath(event.path || "/target/login"),
    };
  }

  if (
    event.event_type === "insider_login" ||
    event.event_type === "insider_access" ||
    event.event_type === "insider_download" ||
    event.event_type === "insider_suspend"
  ) {
    const level = event.level || "LOW RISK";
    const status = level === "HIGH RISK" ? "HIGH RISK" : level === "MEDIUM RISK" ? "MEDIUM RISK" : "SAFE";
    const path = event.path || "/internal/access";
    return {
      status,
      action: event.action || (level === "HIGH RISK" ? "SUSPEND ACCOUNT" : "MONITOR"),
      risk_score: Number(event.risk_score || (level === "HIGH RISK" ? 90 : level === "MEDIUM RISK" ? 55 : 20)),
      confidence: 1,
      scenario: scenarioFromPath(path),
      route: routeForPath(path),
    };
  }

  return null;
}

function ScenarioPills({ scenario, setScenario, running }) {
  return (
    <div style={scenarioStripStyle}>
      {Object.entries(SCENARIOS).map(([key, item]) => (
        <button
          key={key}
          type="button"
          onClick={() => setScenario(key)}
          disabled={running}
          style={{
            ...scenarioPillStyle,
            borderColor: scenario === key ? item.tone === "critical" ? "rgba(248,113,113,0.8)" : "rgba(34,197,94,0.7)" : "rgba(148,163,184,0.28)",
            background:
              scenario === key
                ? item.tone === "critical"
                  ? "linear-gradient(135deg, rgba(127,29,29,0.88), rgba(220,38,38,0.84))"
                  : "linear-gradient(135deg, rgba(6,95,70,0.88), rgba(20,184,166,0.78))"
                : "rgba(15,23,42,0.78)",
            color: scenario === key ? "#fff" : "#cbd5e1",
          }}
        >
          {item.label}
        </button>
      ))}
    </div>
  );
}

function AttackSurfacePanel({ metrics, trend }) {
  const arrow = (current, previous) => {
    if (current > previous) return "▲";
    if (current < previous) return "▼";
    return "•";
  };

  const colorByTrend = (current, previous) => {
    if (current > previous) return SEVERITY_COLORS.critical;
    if (current < previous) return SEVERITY_COLORS.normal;
    return "#94a3b8";
  };

  return (
    <section className="anim-panel panel-card" style={panelStyle}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Current Attack Surface</h3>
        <span className="subtle-tag">Auto-updating</span>
      </div>
      <div style={metricsGridStyle}>
        <MetricCard
          label="Response Time"
          value={`${metrics.response_time_ms} ms`}
          delta={arrow(metrics.response_time_ms, trend.response_time_ms)}
          deltaColor={colorByTrend(metrics.response_time_ms, trend.response_time_ms)}
        />
        <MetricCard
          label="CPU Usage"
          value={`${metrics.cpu_usage}%`}
          delta={arrow(metrics.cpu_usage, trend.cpu_usage)}
          deltaColor={colorByTrend(metrics.cpu_usage, trend.cpu_usage)}
        />
        <MetricCard
          label="Memory Usage"
          value={`${metrics.memory_usage}%`}
          delta={arrow(metrics.memory_usage, trend.memory_usage)}
          deltaColor={colorByTrend(metrics.memory_usage, trend.memory_usage)}
        />
        <MetricCard
          label="Retry Count"
          value={metrics.retry_count}
          delta={arrow(metrics.retry_count, trend.retry_count)}
          deltaColor={colorByTrend(metrics.retry_count, trend.retry_count)}
        />
      </div>
    </section>
  );
}

function MetricCard({ label, value, delta, deltaColor }) {
  return (
    <div style={metricCardStyle}>
      <div style={{ ...metricLabelStyle }}>{label}</div>
      <div style={metricValueStyle}>{value}</div>
      <div style={{ ...metricDeltaStyle, color: deltaColor }}>{delta}</div>
    </div>
  );
}

function NetworkMap({ activeNode = "internet", breached = false, attackPath = null }) {
  const pathSegments = attackPath?.route?.length > 1 ? routeToEdges(attackPath.route) : [];
  const attackProgress = attackPath?.progress ?? 0;
  const packetCount = attackPath?.pulseCount ?? 2;

  return (
    <section className="anim-panel panel-card" style={panelStyle}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Network Map</h3>
        <span className="subtle-tag">Live topology</span>
      </div>
      <div style={networkMapWrapStyle}>
        <svg viewBox="0 0 100 100" style={networkSvgStyle}>
          <defs>
            <linearGradient id="attackGlow" x1="0%" y1="0%" x2="100%" y2="0%">
              <stop offset="0%" stopColor="#f8fafc" stopOpacity="0.95" />
              <stop offset="35%" stopColor="#38bdf8" stopOpacity="0.95" />
              <stop offset="70%" stopColor="#f59e0b" stopOpacity="0.95" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.98" />
            </linearGradient>
            <filter id="attackBlur" x="-30%" y="-30%" width="160%" height="160%">
              <feGaussianBlur stdDeviation="1.4" />
            </filter>
          </defs>

          {NETWORK_EDGES.map(([from, to]) => {
            const source = NETWORK_NODES.find((n) => n.id === from);
            const target = NETWORK_NODES.find((n) => n.id === to);
            const edgeActive = activeNode === from || activeNode === to || breached;
            return (
              <line
                key={`${from}-${to}`}
                x1={source.x}
                y1={source.y}
                x2={target.x}
                y2={target.y}
                stroke={edgeActive ? (breached ? "#ef4444" : "#38bdf8") : "#334155"}
                strokeWidth={edgeActive ? 1.9 : 1.1}
                strokeDasharray={breached ? "2 2" : "0"}
                opacity={edgeActive ? 1 : 0.55}
              />
            );
          })}

          {pathSegments.map((segment, index) => {
            const source = getNodePosition(segment.from);
            const target = getNodePosition(segment.to);
            const segmentActive = attackPath && attackProgress >= index;

            return (
              <g key={`${segment.from}-${segment.to}`}>
                <line
                  x1={source.x}
                  y1={source.y}
                  x2={target.x}
                  y2={target.y}
                  stroke={segmentActive ? "url(#attackGlow)" : "#1f2937"}
                  strokeWidth={segmentActive ? 3.2 : 1.4}
                  strokeLinecap="round"
                  strokeDasharray={segmentActive ? "4 4" : "0"}
                  opacity={segmentActive ? 1 : 0.35}
                />
                {segmentActive ? (
                  <line
                    x1={source.x}
                    y1={source.y}
                    x2={target.x}
                    y2={target.y}
                    stroke={breached ? "#ef4444" : "#38bdf8"}
                    strokeWidth={1.1}
                    strokeLinecap="round"
                    opacity={0.78}
                    style={{
                      strokeDasharray: 16,
                      strokeDashoffset: attackPath?.pulseTick ? 16 - (attackPath.pulseTick % 16) : 0,
                    }}
                  />
                ) : null}
              </g>
            );
          })}

          {pathSegments.map((segment, index) => {
            if (!attackPath || attackProgress < index) return null;
            const source = getNodePosition(segment.from);
            const target = getNodePosition(segment.to);
            const factor = clamp(attackProgress - index, 0, 1);
            const x = source.x + (target.x - source.x) * factor;
            const y = source.y + (target.y - source.y) * factor;
            return (
              <circle
                key={`packet-${segment.from}-${segment.to}`}
                cx={x}
                cy={y}
                r={index === pathSegments.length - 1 && breached ? 4.3 : 3.2}
                fill={index === pathSegments.length - 1 && breached ? "#ef4444" : "#38bdf8"}
                filter="url(#attackBlur)"
                opacity={0.95}
              />
            );
          })}

          {attackPath ? (
            <g opacity="0.95">
              {Array.from({ length: packetCount }).map((_, index) => {
                const orbit = (attackProgress + index * 0.32) % Math.max(pathSegments.length, 1);
                const segmentIndex = Math.min(pathSegments.length - 1, Math.floor(orbit));
                const segment = pathSegments[segmentIndex];
                if (!segment) return null;
                const source = getNodePosition(segment.from);
                const target = getNodePosition(segment.to);
                const localProgress = orbit - segmentIndex;
                const x = source.x + (target.x - source.x) * localProgress;
                const y = source.y + (target.y - source.y) * localProgress;
                return (
                  <circle
                    key={`pulse-${index}`}
                    cx={x}
                    cy={y}
                    r={index % 2 === 0 ? 1.6 : 2}
                    fill={index % 2 === 0 ? "#f8fafc" : "#f59e0b"}
                    filter="url(#attackBlur)"
                    opacity={0.8}
                  />
                );
              })}
            </g>
          ) : null}

          {NETWORK_NODES.map((node) => {
            const isActive = activeNode === node.id;
            const isBreach = breached && node.id === "internet";
            const isRouteNode = attackPath?.route?.includes(node.id);
            return (
              <g key={node.id} transform={`translate(${node.x}, ${node.y})`}>
                {isRouteNode ? (
                  <circle
                    r={8.8}
                    fill="none"
                    stroke={breached ? "#ef4444" : "#38bdf8"}
                    strokeOpacity="0.35"
                    strokeWidth="0.9"
                  />
                ) : null}
                <circle
                  r={isActive || isRouteNode ? 7.6 : 6}
                  fill={isBreach ? "#ef4444" : isActive ? "#38bdf8" : "#0f172a"}
                  stroke={isBreach ? "#fecaca" : isRouteNode ? "#7dd3fc" : isActive ? "#fff" : "#64748b"}
                  strokeWidth={isRouteNode ? 1.5 : 1}
                  filter={isActive || isRouteNode ? "url(#attackBlur)" : undefined}
                />
                {isRouteNode ? (
                  <circle
                    r={11.5}
                    fill="none"
                    stroke={breached ? "#ef4444" : "#38bdf8"}
                    strokeOpacity="0.22"
                    strokeDasharray="2 3"
                    strokeWidth="0.8"
                  >
                    <animate attributeName="r" values="10;13;10" dur="1.4s" repeatCount="indefinite" />
                    <animate attributeName="stroke-opacity" values="0.1;0.5;0.1" dur="1.4s" repeatCount="indefinite" />
                  </circle>
                ) : null}
                <text x="0" y="16" textAnchor="middle" fill="#cbd5e1" fontSize="3.2" fontWeight="600">
                  {node.label}
                </text>
                {isBreach && (
                  <text x="0" y="-10" textAnchor="middle" fill="#f87171" fontSize="6" fontWeight="800">
                    X
                  </text>
                )}
              </g>
            );
          })}
        </svg>
      </div>
    </section>
  );
}

function LogsPanel({ logs, logsRef }) {
  return (
    <section className="anim-panel panel-card" style={panelStyle}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Live System Logs</h3>
        <span className="subtle-tag">Auto-feed</span>
      </div>
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

function ResultPanel({ prediction, scenario, loading, simulating, error, timeline }) {
  const meterRef = useRef(null);
  const statusColor = useMemo(() => {
    if (!prediction?.status) return "#94a3b8";
    if (prediction.status === "SAFE") return SEVERITY_COLORS.normal;
    if (prediction.status === "MEDIUM RISK") return SEVERITY_COLORS.warning;
    return SEVERITY_COLORS.critical;
  }, [prediction]);

  const score = Math.max(0, Math.min(100, Number(prediction?.risk_score || 0)));
  const scenarioTone = SCENARIOS[scenario]?.tone || "normal";

  useEffect(() => {
    if (!meterRef.current) return;
    gsap.to(meterRef.current, {
      width: `${score}%`,
      duration: 0.8,
      ease: "power3.out",
    });
  }, [score]);

  useEffect(() => {
    if (!prediction?.status) return;
    gsap.fromTo(
      ".status-glow",
      { scale: 0.985, boxShadow: "0 0 0 rgba(0,0,0,0)" },
      {
        scale: 1,
        boxShadow: `0 0 22px ${statusColor}55`,
        duration: 0.45,
        yoyo: true,
        repeat: 1,
        ease: "power1.out",
      }
    );
  }, [prediction, statusColor]);

  return (
    <section className="anim-panel panel-card" style={panelStyle}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Incident Response</h3>
        <span className="subtle-tag">{SCENARIOS[scenario]?.label || "Scenario"}</span>
      </div>

      <div className={`status-glow incident-${scenarioTone}`} style={{ ...incidentBannerStyle, borderColor: `${statusColor}55` }}>
        <div style={{ ...incidentStatusStyle, color: statusColor }}>
          {prediction?.status || "Awaiting scenario run"}
        </div>
        <div style={incidentMetaStyle}>Action: <strong>{prediction?.action || "-"}</strong></div>
        <div style={incidentMetaStyle}>Confidence: {typeof prediction?.confidence === "number" ? `${(prediction.confidence * 100).toFixed(1)}%` : "-"}</div>
        <div style={{ marginTop: 12 }}>
          <div style={incidentMetaStyle}>Risk Score: {score.toFixed(1)}/100</div>
          <div style={meterOuterStyle}>
            <div
              ref={meterRef}
              style={{ ...meterInnerStyle, width: "0%", background: "linear-gradient(90deg, #20c997, #f59e0b, #ef4444)" }}
            />
          </div>
        </div>
      </div>

      {loading ? <div style={noticeStyle}>Contacting model...</div> : null}
      {simulating ? <div style={{ ...noticeStyle, color: "#f59e0b" }}>Running live incident simulation...</div> : null}
      {error ? <div style={{ ...noticeStyle, color: "#f87171" }}>{error}</div> : null}

      <div style={timelineMiniWrapStyle}>
        {timeline.slice(-6).map((item) => (
          <div key={item.id} style={timelineMiniItemStyle}>
            <span style={{ color: SEVERITY_COLORS[item.severity], fontWeight: 800 }}>[{item.severity.toUpperCase()}]</span>
            <span style={{ color: "#cbd5e1" }}>{item.message}</span>
          </div>
        ))}
      </div>
    </section>
  );
}

function ThreatTimeline({ events }) {
  return (
    <section className="anim-panel panel-card" style={{ ...panelStyle, marginTop: 2 }}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Threat Timeline</h3>
        <span className="subtle-tag">Narrative view</span>
      </div>
      <div style={timelineWrapStyle}>
        {events.map((event, index) => (
          <div key={event.id} style={timelineItemWrapStyle}>
            <div style={{ ...timelineDotStyle, background: SEVERITY_COLORS[event.severity] }} />
            <div style={timelineTextStyle}>
              <div style={{ color: SEVERITY_COLORS[event.severity], fontWeight: 800 }}>
                [{event.timestamp}] {event.tag}
              </div>
              <div style={{ color: "#cbd5e1", marginTop: 4 }}>{event.message}</div>
            </div>
            {index < events.length - 1 && <div style={timelineConnectorStyle} />}
          </div>
        ))}
      </div>
    </section>
  );
}

function InsiderThreatMonitor({ alerts }) {
  return (
    <section className="anim-panel panel-card" style={{ ...panelStyle, marginTop: 14 }}>
      <div className="panel-head">
        <h3 style={panelTitleStyle}>Insider Threat Monitor</h3>
        <span className="subtle-tag">Socket.IO live feed</span>
      </div>
      <div style={timelineWrapStyle}>
        {alerts.length === 0 ? (
          <div style={{ color: "#94a3b8", fontSize: 13 }}>No insider threat events received yet.</div>
        ) : (
          alerts.map((alert) => (
            <div key={alert.id} style={{ ...endCardStyle, marginTop: 0, borderColor: `${alert.color}55` }}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", gap: 10 }}>
                <strong style={{ color: alert.color, fontSize: 16 }}>
                  {alert.username} - {alert.level}
                </strong>
                <span style={{ ...subtleTagStyle, borderColor: `${alert.color}55`, color: alert.color }}>
                  Risk {alert.risk_score}
                </span>
              </div>
              <div style={incidentMetaStyle}>Action: <strong>{alert.action}</strong></div>
              <div style={incidentMetaStyle}>Time: {alert.timestamp}</div>
              <div style={{ marginTop: 8, display: "grid", gap: 5 }}>
                {(alert.anomalies || []).map((entry, idx) => (
                  <div key={`${alert.id}-${idx}`} style={{ fontSize: 12, color: "#cbd5e1" }}>
                    - {entry}
                  </div>
                ))}
              </div>
            </div>
          ))
        )}
      </div>
    </section>
  );
}

export default function CyberMonitoringDashboard({ apiBaseUrl = "http://localhost:8001" }) {
  const rootRef = useRef(null);
  const logsRef = useRef(null);
  const pulseRef = useRef(null);
  const attackTimerRef = useRef(null);
  const liveFeedTimerRef = useRef(null);
  const lastEventEpochRef = useRef(0);
  const lastIncidentEpochRef = useRef(0);
  const lastIncidentSampleRef = useRef("");

  const [scenario, setScenario] = useState("normal");
  const [liveMode, setLiveMode] = useState(true);
  const [metrics, setMetrics] = useState(createInitialMetrics());
  const [trend, setTrend] = useState(createInitialMetrics());
  const [prediction, setPrediction] = useState(null);
  const [loading, setLoading] = useState(false);
  const [simulating, setSimulating] = useState(false);
  const [error, setError] = useState("");
  const [logs, setLogs] = useState(() => [
    { id: Date.now(), timestamp: nowLabel(), message: "Security console online", severity: "normal" },
  ]);
  const [riskHistory, setRiskHistory] = useState([]);
  const [metricsHistory, setMetricsHistory] = useState([]);
  const [timeline, setTimeline] = useState([]);
  const [networkFocus, setNetworkFocus] = useState("internet");
  const [breached, setBreached] = useState(false);
  const [attackPath, setAttackPath] = useState(null);
  const [insiderAlerts, setInsiderAlerts] = useState([]);

  const addLog = (message, severity = "normal") => {
    setLogs((prev) => {
      const next = [...prev, { id: Date.now() + Math.random(), timestamp: nowLabel(), message, severity }];
      return next.slice(-160);
    });
  };

  const addTimelineEvent = (tag, message, severity = "normal") => {
    setTimeline((prev) => [
      ...prev,
      { id: Date.now() + Math.random(), timestamp: nowLabel(), tag, message, severity },
    ].slice(-12));
  };

  const updateMetrics = (nextMetrics) => {
    setTrend((prev) => ({ ...metrics }));
    setMetrics(nextMetrics);
    setMetricsHistory((prev) => [
      ...prev.slice(-39),
      { time: nowLabel(), cpu: Number(nextMetrics.cpu_usage), memory: Number(nextMetrics.memory_usage) },
    ]);
  };

  useEffect(() => {
    const ctx = gsap.context(() => {
      gsap.from(".anim-hero", {
        y: -18,
        opacity: 0,
        duration: 0.7,
        ease: "power3.out",
      });
      gsap.from(".anim-panel", {
        y: 18,
        opacity: 0,
        stagger: 0.08,
        duration: 0.65,
        delay: 0.08,
        ease: "power2.out",
      });
      if (pulseRef.current) {
        gsap.to(pulseRef.current, {
          scale: 1.2,
          opacity: 0.45,
          repeat: -1,
          yoyo: true,
          duration: 0.9,
          ease: "sine.inOut",
        });
      }
    }, rootRef);

    return () => ctx.revert();
  }, []);

  useEffect(() => {
    if (!logsRef.current) return;
    logsRef.current.scrollTop = logsRef.current.scrollHeight;
    const last = logsRef.current.querySelector(".log-item:last-child");
    if (last) {
      gsap.fromTo(last, { x: -14, opacity: 0.4 }, { x: 0, opacity: 1, duration: 0.25, ease: "power1.out" });
    }
  }, [logs]);

  useEffect(() => {
    if (simulating || liveMode) return;

    const pool = [
      { message: "Normal API request", severity: "normal" },
      { message: "Session token validated", severity: "normal" },
      { message: "CPU usage spike detected", severity: "warning" },
      { message: "Memory pressure increasing", severity: "warning" },
      { message: "Multiple failed login attempts", severity: "critical" },
      { message: "Unusual retry burst detected", severity: "critical" },
    ];

    liveFeedTimerRef.current = setInterval(() => {
      const item = pool[Math.floor(Math.random() * pool.length)];
      addLog(item.message, item.severity);

      setMetrics((prev) => {
        const cpu = clamp(prev.cpu_usage + (Math.random() * 6 - 2), 8, 100);
        const memory = clamp(prev.memory_usage + (Math.random() * 4 - 1), 10, 100);
        const responseTime = clamp(prev.response_time_ms + (Math.random() * 180 - 80), 85, 9999);
        return {
          ...prev,
          cpu_usage: Math.round(cpu),
          memory_usage: Math.round(memory),
          response_time_ms: Math.round(responseTime),
          retry_count: prev.retry_count,
        };
      });
    }, 2500);

    return () => clearInterval(liveFeedTimerRef.current);
  }, [simulating, liveMode]);

  useEffect(() => {
    if (liveMode) return;
    const current = SCENARIOS[scenario];
    setBreached(false);
    setNetworkFocus("internet");
    setAttackPath(null);
    setMetrics((prev) => ({
      ...prev,
      activeScenario: scenario,
      response_time_ms: current.payload.response_time_ms,
      cpu_usage: current.payload.cpu_usage,
      memory_usage: current.payload.memory_usage,
      retry_count: current.payload.retry_count,
      status_code: current.payload.status_code,
    }));
  }, [scenario, liveMode]);

  useEffect(() => {
    if (!liveMode) return;

    const sync = async () => {
      try {
        const [eventsRes, overviewRes] = await Promise.all([
          fetch(`${apiBaseUrl}/security/events?limit=180`),
          fetch(`${apiBaseUrl}/security/overview`),
        ]);

        if (!eventsRes.ok || !overviewRes.ok) {
          throw new Error("Unable to fetch security telemetry");
        }

        const eventsBody = await eventsRes.json();
        const overview = await overviewRes.json();
        const events = Array.isArray(eventsBody.events) ? eventsBody.events : [];

        const unseen = events.filter((event) => Number(event.epoch || 0) > lastEventEpochRef.current);
        if (unseen.length) {
          lastEventEpochRef.current = Number(unseen[unseen.length - 1].epoch || lastEventEpochRef.current);

          setLogs((prev) => {
            const mapped = unseen.map((event) => ({
              id: `${event.epoch}-${event.source}-${event.event_type}`,
              timestamp: event.timestamp || nowLabel(),
              message: `${event.source}: ${event.message}`,
              severity: event.severity || "normal",
            }));
            return [...prev, ...mapped].slice(-220);
          });

          setTimeline((prev) => {
            const mapped = unseen.slice(-10).map((event) => ({
              id: `${event.epoch}-${event.event_type}`,
              timestamp: event.timestamp || nowLabel(),
              tag: (event.event_type || "event").toUpperCase(),
              message: event.message,
              severity: event.severity || "normal",
            }));
            return [...prev, ...mapped].slice(-18);
          });
        }

        const assessmentEvents = events.filter(
          (event) =>
            event.event_type === "traffic" ||
            event.event_type === "auto_block" ||
            event.event_type === "insider_login" ||
            event.event_type === "insider_access" ||
            event.event_type === "insider_download" ||
            event.event_type === "insider_suspend"
        );

        // Use newest event overall (epoch) so Incident Response reflects
        // current real-traffic state instead of sticking to older block events.
        // If epochs are equal, prioritize stronger event types.
        const eventPriority = (eventType) => {
          if (eventType === "insider_suspend" || eventType === "auto_block") return 4;
          if (eventType === "insider_download" || eventType === "insider_access" || eventType === "insider_login") return 3;
          if (eventType === "traffic") return 2;
          return 0;
        };
        const latest = [...assessmentEvents]
          .sort((a, b) => {
            const epochDiff = Number(a.epoch || 0) - Number(b.epoch || 0);
            if (epochDiff !== 0) return epochDiff;
            return eventPriority(a.event_type) - eventPriority(b.event_type);
          })
          .pop() || null;
        const latestEpoch = Number(latest?.epoch || 0);
        const latestAssessment = assessmentFromSecurityEvent(latest);

        // Guard against overlapping poll responses applying stale SAFE state.
        if (latest && latestAssessment && latestEpoch >= lastIncidentEpochRef.current) {
          lastIncidentEpochRef.current = latestEpoch;
          const latestRisk = Number(latestAssessment.risk_score || 0);
          const sampleKey = `${latestEpoch}|${latest.event_type}|${latestAssessment.status}|${latestRisk}`;
          setScenario(latestAssessment.scenario);
          setPrediction({
            status: latestAssessment.status,
            action: latestAssessment.action,
            confidence: latestAssessment.confidence,
            risk_score: latestRisk,
          });
          if (sampleKey !== lastIncidentSampleRef.current) {
            lastIncidentSampleRef.current = sampleKey;
            setRiskHistory((prev) => [...prev.slice(-49), { time: latest.timestamp || nowLabel(), risk: latestRisk }]);
          }
          setBreached((latestAssessment.status || "").includes("HIGH"));

          const route = latestAssessment.route;
          setNetworkFocus(route[route.length - 1]);
          setAttackPath({
            route,
            progress: Math.max(1, route.length - 1),
            pulseCount: (latestAssessment.status || "").includes("HIGH") ? 5 : 3,
            pulseTick: Date.now() / 120,
          });
        }

        const topSource = Array.isArray(overview.active_sources) ? overview.active_sources[0] : null;
        if (topSource) {
          const next = {
            response_time_ms: Math.max(80, 140 + topSource.requests_in_window * 18),
            cpu_usage: Math.min(100, 16 + topSource.requests_in_window * 3.2),
            memory_usage: Math.min(100, 28 + topSource.requests_in_window * 2),
            retry_count: topSource.failures || 0,
            status_code: 200,
            activeScenario: "live",
          };
          setMetrics((prev) => {
            const snapshot = { ...prev };
            Promise.resolve().then(() => setTrend(snapshot));
            return next;
          });
        }
        setError("");
      } catch (err) {
        setError(err.message || "Failed to sync live telemetry");
      }
    };

    sync();
    const interval = setInterval(sync, 1300);
    return () => clearInterval(interval);
  }, [apiBaseUrl, liveMode]);

  useEffect(() => {
    const socket = io(apiBaseUrl, {
      transports: ["websocket", "polling"],
      reconnection: true,
    });

    socket.on("insider_threat", (payload) => {
      const level = payload?.level || "LOW RISK";
      const color = level.includes("HIGH")
        ? "#ef4444"
        : level.includes("MEDIUM")
          ? "#f59e0b"
          : "#22c55e";
      setInsiderAlerts((prev) => [
        {
          id: `${Date.now()}-${Math.random()}`,
          username: payload?.username || "unknown",
          risk_score: Number(payload?.risk_score || 0),
          level,
          action: payload?.action || "MONITOR",
          anomalies: Array.isArray(payload?.anomalies) ? payload.anomalies : [],
          timestamp: payload?.timestamp || nowLabel(),
          color,
        },
        ...prev,
      ].slice(0, 20));
    });

    return () => {
      socket.disconnect();
    };
  }, [apiBaseUrl]);

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

  const runPrediction = async (payload, sourceLabel = "Scenario") => {
    setLoading(true);
    setError("");

    try {
      const result = await callPredict(payload);
      setPrediction(result);
      setRiskHistory((prev) => [...prev.slice(-39), { time: nowLabel(), risk: Number(result.risk_score || 0) }]);
      const severity = severityFromStatus(result.status);
      addLog(`${sourceLabel} -> ${result.status} (${result.action})`, severity);
      addTimelineEvent(result.status, `${sourceLabel} ended with ${result.action}`, severity);
      if (result.status === "HIGH RISK") {
        setBreached(true);
        setNetworkFocus("firewall");
      }
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

  const simulateScenario = async (key) => {
    if (attackTimerRef.current) {
      clearTimeout(attackTimerRef.current);
    }
    if (simulating || loading) return;

    const selected = SCENARIOS[key];
    setScenario(key);
    setSimulating(true);
    setError("");
    setBreached(false);
    const selectedRoute = getRouteForScenario(key);
    const routeSegments = routeToEdges(selectedRoute);

    try {
      addTimelineEvent("START", `Scenario selected: ${selected.label}`, "normal");
      addLog(`Scenario engaged: ${selected.label}`, "normal");
      await sleep(900);

      const replaySeries = selected.series;
      for (let i = 0; i < replaySeries.length; i += 1) {
        const nextRisk = replaySeries[i];
        const current = selected.payload;

        setNetworkFocus(i < 1 ? selectedRoute[0] : i < 3 ? selectedRoute[Math.min(1, selectedRoute.length - 1)] : selectedRoute[selectedRoute.length - 1]);
        setAttackPath({
          route: selectedRoute,
          progress: Math.min(routeSegments.length, i * 0.8 + 0.25),
          pulseCount: key === "ddos" ? 4 : 3,
          pulseTick: i * 3,
        });
        setMetrics((prev) => ({
          ...prev,
          activeScenario: key,
          response_time_ms: clamp(current.response_time_ms + i * 180, 85, 9999),
          cpu_usage: clamp(current.cpu_usage - 16 + i * 9, 8, 100),
          memory_usage: clamp(current.memory_usage - 10 + i * 7, 10, 100),
          retry_count: current.retry_count + i * (key === "normal" ? 0 : 2),
          status_code: current.status_code,
        }));

        if (i === 1) addLog("Telemetry drift detected", "warning");
        if (i === 2) addLog("Firewall rules escalating", "warning");
        if (i === 3) addLog("Threat classifier confidence rising", "critical");
        if (i === 4) addLog("Preparing automated response", "critical");

        setRiskHistory((prev) => [...prev.slice(-39), { time: nowLabel(), risk: nextRisk }]);
        addTimelineEvent(
          i === replaySeries.length - 1 ? "BLOCKED" : i < 2 ? "WATCH" : i < 4 ? "ALERT" : "CRITICAL",
          `Risk progressed to ${nextRisk}/100`,
          nextRisk > 70 ? "critical" : nextRisk > 35 ? "warning" : "normal"
        );

        await sleep(850);
      }

      const result = await runPrediction(selected.payload, selected.label);
      if (result.status === "HIGH RISK") {
        setNetworkFocus("internet");
        setAttackPath({
          route: selectedRoute,
          progress: routeSegments.length,
          pulseCount: key === "ddos" ? 5 : 3,
          pulseTick: routeSegments.length * 4,
        });
        addLog("Source IP blocked automatically", "critical");
        addTimelineEvent("BLOCKED", "Source IP blocked automatically", "critical");
      }
    } catch (_err) {
      // handled in runPrediction
    } finally {
      attackTimerRef.current = setTimeout(() => {
        setAttackPath(null);
      }, 1400);
      setSimulating(false);
    }
  };

  return (
    <div ref={rootRef} style={rootStyle}>
      <div className="anim-hero" style={heroStyle}>
        <div>
          <div style={eyebrowStyle}>AegisAI Monitoring</div>
          <h1 style={{ margin: 0, fontSize: 28 }}>Realtime Threat Operations Console</h1>
          <p style={{ marginTop: 8, marginBottom: 0, color: "#94a3b8", maxWidth: 760 }}>
            Blue Team mode now consumes real traffic telemetry from the protected target app while Red Team launches
            actual HTTP attack bursts from a separate app.
          </p>
        </div>
        <div style={liveBadgeStyle}>
          <span ref={pulseRef} style={pulseDotStyle} />
          {liveMode ? "LIVE DEFENSE MODE" : "SIMULATION MODE"}
        </div>
      </div>

      <div style={{ display: "flex", gap: 10, marginBottom: 14 }}>
        <button
          type="button"
          style={toggleStyle}
          onClick={() => {
            lastIncidentEpochRef.current = 0;
            lastIncidentSampleRef.current = "";
            setError("");
            setLiveMode(true);
          }}
        >
          Use Real Traffic Mode
        </button>
        <button type="button" style={toggleStyle} onClick={() => setLiveMode(false)}>
          Use Simulator Mode
        </button>
      </div>

      {!liveMode ? <ScenarioPills scenario={scenario} setScenario={simulateScenario} running={simulating || loading} /> : null}

      <div style={topGridStyle}>
        <AttackSurfacePanel metrics={metrics} trend={trend} />
        <NetworkMap activeNode={networkFocus} breached={breached} attackPath={attackPath} />
      </div>

      <div style={gridStyle}>
        <LogsPanel logs={logs} logsRef={logsRef} />
        <ResultPanel prediction={prediction} scenario={scenario} loading={loading} simulating={simulating} error={error} timeline={timeline} />
      </div>

      <ThreatTimeline events={timeline} />

      <section className="anim-panel panel-card" style={{ ...panelStyle, marginTop: 14 }}>
        <div className="panel-head">
          <h3 style={panelTitleStyle}>Risk Score Over Time</h3>
          <span className="subtle-tag">Animated response curve</span>
        </div>
        <div style={{ width: "100%", height: 240 }}>
          <ResponsiveContainer>
            <LineChart data={riskHistory}>
              <CartesianGrid strokeDasharray="3 3" stroke="#243244" />
              <XAxis dataKey="time" stroke="#94a3b8" />
              <YAxis domain={[0, 100]} stroke="#94a3b8" />
              <Tooltip
                contentStyle={{ background: "#0b1220", border: "1px solid #334155", borderRadius: 10 }}
                labelStyle={{ color: "#cbd5e1" }}
                itemStyle={{ color: "#e2e8f0" }}
              />
              <Line type="monotone" dataKey="risk" stroke="#00a39a" strokeWidth={2.6} dot={{ r: 2 }} />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </section>

      <InsiderThreatMonitor alerts={insiderAlerts} />
    </div>
  );
}

const rootStyle = {
  fontFamily: "Space Grotesk, sans-serif",
  color: "#e2e8f0",
  maxWidth: 1440,
  margin: "0 auto",
  padding: 20,
  borderRadius: 18,
};

const heroStyle = {
  display: "flex",
  justifyContent: "space-between",
  alignItems: "center",
  marginBottom: 14,
  gap: 12,
};

const eyebrowStyle = {
  textTransform: "uppercase",
  letterSpacing: 2,
  color: "#38bdf8",
  fontSize: 12,
  fontWeight: 700,
  marginBottom: 8,
};

const liveBadgeStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: 8,
  fontWeight: 800,
  color: "#e2e8f0",
  borderRadius: 999,
  border: "1px solid rgba(148,163,184,0.26)",
  padding: "10px 14px",
  background: "rgba(15,23,42,0.92)",
  boxShadow: "0 7px 18px rgba(0,0,0,0.35)",
  whiteSpace: "nowrap",
};

const pulseDotStyle = {
  width: 10,
  height: 10,
  borderRadius: "50%",
  background: "#20c997",
  display: "inline-block",
};

const scenarioStripStyle = {
  display: "grid",
  gridTemplateColumns: "repeat(5, minmax(0, 1fr))",
  gap: 10,
  marginBottom: 14,
};

const scenarioPillStyle = {
  borderRadius: 14,
  border: "1px solid rgba(148,163,184,0.28)",
  padding: "12px 10px",
  cursor: "pointer",
  fontWeight: 800,
  boxShadow: "0 12px 28px rgba(0,0,0,0.18)",
  transition: "transform 180ms ease, box-shadow 180ms ease, background 180ms ease",
};

const topGridStyle = {
  display: "grid",
  gridTemplateColumns: "1.1fr 0.9fr",
  gap: 14,
  marginBottom: 14,
};

const gridStyle = {
  display: "grid",
  gridTemplateColumns: "1fr 1fr",
  gap: 14,
  marginBottom: 14,
};

const panelStyle = {
  borderRadius: 18,
  border: "1px solid rgba(148,163,184,0.18)",
  background: "rgba(15,23,42,0.92)",
  padding: 16,
  minHeight: 250,
  boxShadow: "0 18px 34px rgba(0,0,0,0.32)",
};

const panelTitleStyle = {
  marginTop: 0,
  marginBottom: 0,
  fontSize: 16,
  letterSpacing: 0.2,
  color: "#f8fafc",
};

const metricsGridStyle = {
  marginTop: 12,
  display: "grid",
  gridTemplateColumns: "repeat(2, minmax(0, 1fr))",
  gap: 10,
};

const metricCardStyle = {
  borderRadius: 14,
  padding: 12,
  background: "rgba(2,6,23,0.9)",
  border: "1px solid rgba(148,163,184,0.18)",
};

const metricLabelStyle = {
  fontSize: 12,
  color: "#94a3b8",
};

const metricValueStyle = {
  fontSize: 19,
  fontWeight: 800,
  marginTop: 6,
};

const metricDeltaStyle = {
  fontSize: 14,
  fontWeight: 900,
  marginTop: 4,
};

const networkMapWrapStyle = {
  marginTop: 12,
  minHeight: 270,
  borderRadius: 14,
  background: "radial-gradient(circle at 40% 20%, rgba(56,189,248,0.12), transparent 34%), linear-gradient(180deg, rgba(2,6,23,0.95), rgba(15,23,42,0.95))",
  border: "1px solid rgba(148,163,184,0.16)",
  overflow: "hidden",
};

const networkSvgStyle = {
  width: "100%",
  height: 270,
  display: "block",
};

const logsContainerStyle = {
  height: 450,
  overflowY: "auto",
  border: "1px solid rgba(148,163,184,0.18)",
  borderRadius: 14,
  padding: 12,
  background: "rgba(2,6,23,0.9)",
};

const logRowStyle = {
  display: "flex",
  gap: 8,
  fontSize: 13,
  marginBottom: 8,
  alignItems: "baseline",
};

const logTimestampStyle = {
  fontFamily: "JetBrains Mono, monospace",
  minWidth: 84,
};

const incidentBannerStyle = {
  borderRadius: 14,
  border: "1px solid rgba(148,163,184,0.18)",
  background: "rgba(2,6,23,0.96)",
  padding: 14,
};

const incidentStatusStyle = {
  fontSize: 28,
  fontWeight: 900,
  letterSpacing: 1,
};

const incidentMetaStyle = {
  fontSize: 13,
  color: "#cbd5e1",
  marginTop: 7,
};

const meterOuterStyle = {
  marginTop: 6,
  height: 11,
  borderRadius: 999,
  background: "#1e293b",
  overflow: "hidden",
};

const meterInnerStyle = {
  height: "100%",
};

const noticeStyle = {
  marginTop: 10,
  fontSize: 13,
  color: "#94a3b8",
};

const timelineMiniWrapStyle = {
  marginTop: 12,
  display: "grid",
  gap: 8,
  paddingTop: 12,
  borderTop: "1px solid rgba(148,163,184,0.14)",
};

const timelineMiniItemStyle = {
  display: "grid",
  gap: 4,
  fontSize: 12,
};

const timelineWrapStyle = {
  marginTop: 12,
  borderRadius: 14,
  background: "rgba(2,6,23,0.88)",
  border: "1px solid rgba(148,163,184,0.18)",
  padding: 14,
  display: "grid",
  gap: 14,
};

const timelineItemWrapStyle = {
  position: "relative",
  paddingLeft: 16,
};

const timelineDotStyle = {
  width: 10,
  height: 10,
  borderRadius: "50%",
  position: "absolute",
  left: 0,
  top: 3,
  boxShadow: "0 0 14px rgba(255,255,255,0.12)",
};

const timelineTextStyle = {
  paddingLeft: 6,
};

const timelineConnectorStyle = {
  position: "absolute",
  left: 4,
  top: 16,
  bottom: -16,
  width: 2,
  background: "linear-gradient(180deg, rgba(56,189,248,0.28), rgba(239,68,68,0.18))",
};

const subtleTagStyle = {
  display: "inline-flex",
  alignItems: "center",
  padding: "5px 10px",
  borderRadius: 999,
  border: "1px solid rgba(148,163,184,0.18)",
  color: "#94a3b8",
  fontSize: 12,
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

const endCardStyle = {
  borderRadius: 12,
  border: "1px solid rgba(148,163,184,0.18)",
  background: "rgba(2,6,23,0.9)",
  padding: 12,
  marginTop: 8,
};

const errorStyle = {
  fontSize: 13,
  color: "#f87171",
};

const toggleStyle = {
  border: "1px solid rgba(148,163,184,0.18)",
  background: "rgba(15,23,42,0.84)",
  color: "#e2e8f0",
  borderRadius: 10,
  padding: "8px 12px",
  fontWeight: 800,
  cursor: "pointer",
};

function NetworkBackdrop() {
  return null;
}
