import { useState, useEffect, useRef } from "react";

// ── Simulated data engine (replace with SSE from /mempool/threats/stream) ──

const ATTACK_CATEGORIES = {
  flash_loan: { label: "Flash Loan", color: "#E24B4A", icon: "⚡" },
  reentrancy: { label: "Reentrancy", color: "#EF9F27", icon: "🔄" },
  access_control: { label: "Access Control", color: "#D85A30", icon: "🔐" },
  oracle_manipulation: { label: "Oracle", color: "#D4537E", icon: "📡" },
  price_manipulation: { label: "Price Manip", color: "#378ADD", icon: "📊" },
  governance_attack: { label: "Governance", color: "#7F77DD", icon: "🏛" },
  front_running: { label: "Front-Run", color: "#1D9E75", icon: "🏃" },
  logic_bug: { label: "Logic Bug", color: "#888780", icon: "🐛" },
};

const RISK_LEVELS = {
  critical: { color: "#E24B4A", bg: "rgba(226,75,74,0.12)", pulse: true },
  high: { color: "#EF9F27", bg: "rgba(239,159,39,0.1)", pulse: false },
  medium: { color: "#378ADD", bg: "rgba(55,138,221,0.08)", pulse: false },
  low: { color: "#1D9E75", bg: "rgba(29,158,117,0.06)", pulse: false },
};

const WATCHED_PROTOCOLS = [
  { name: "MockLendingPool", address: "0x8456...630E", chain: "Sepolia", status: "active" },
  { name: "ProtocolGuardian", address: "0x2344...12fE", chain: "Sepolia", status: "active" },
  { name: "Aave V3 Pool", address: "0x8787...4e2", chain: "Mainnet", status: "pending" },
  { name: "Uniswap V3", address: "0x68b3...c45", chain: "Mainnet", status: "pending" },
  { name: "Compound", address: "0x3d98...3b", chain: "Mainnet", status: "pending" },
  { name: "MakerDAO Vat", address: "0x35d1...2b", chain: "Mainnet", status: "pending" },
];

const EXPLOIT_DB_STATS = {
  total: 21, totalLoss: "$3.7B", dateRange: "2016–2026", chains: 6,
  categories: [
    { name: "Access Control", count: 6, loss: "$2.15B" },
    { name: "Flash Loan", count: 6, loss: "$422M" },
    { name: "Oracle Manipulation", count: 2, loss: "$234M" },
    { name: "Governance", count: 2, loss: "$202M" },
    { name: "Reentrancy", count: 4, loss: "$162M" },
    { name: "Price Manipulation", count: 1, loss: "$500M" },
  ],
};

function generateThreat(id) {
  const scenarios = [
    { hash: "0xdead" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x8456...630E", score: 0.95, level: "critical", cats: ["flash_loan", "reentrancy"], action: "PAUSE_CONTRACT", indicators: 5, value: "0.00", desc: "Aave V3 flash loan + withdrawAll() reentrancy combo targeting MockLendingPool" },
    { hash: "0xbeef" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x2344...12fE", score: 1.0, level: "critical", cats: ["access_control"], action: "PAUSE_CONTRACT", indicators: 2, value: "0.00", desc: "upgradeToAndCall() + transferOwnership() — proxy takeover attempt on ProtocolGuardian" },
    { hash: "0xface" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x8456...630E", score: 0.72, level: "high", cats: ["oracle_manipulation", "flash_loan"], action: "ALERT_AND_SIMULATE", indicators: 4, value: "100.00", desc: "getReserves() oracle read + Aave flash loan — oracle manipulation pattern" },
    { hash: "0xcafe" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x8456...630E", score: 0.65, level: "high", cats: ["reentrancy"], action: "ALERT_AND_SIMULATE", indicators: 1, value: "0.00", desc: "withdrawAll() on MockLendingPool — classic DAO-style reentrancy target" },
    { hash: "0xd00d" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x8456...630E", score: 0.45, level: "medium", cats: ["price_manipulation"], action: "ALERT", indicators: 1, value: "1.50", desc: "Uniswap V2 swap on watched pair — monitoring for sandwich pattern" },
    { hash: "0xa1fa" + Math.random().toString(16).slice(2,10), from: "0x" + Math.random().toString(16).slice(2,12), to: "0x8456...630E", score: 1.0, level: "critical", cats: ["flash_loan", "governance_attack"], action: "PAUSE_CONTRACT", indicators: 4, value: "0.00", desc: "Flash loan → propose() + castVote() + execute() — Beanstalk-style governance takeover" },
  ];
  const s = scenarios[id % scenarios.length];
  return { ...s, id, time: new Date(), latency: (Math.random() * 0.3 + 0.05).toFixed(2) };
}

// ── Components ──

function Pulse({ color }) {
  return (
    <span style={{
      display: "inline-block", width: 8, height: 8, borderRadius: "50%",
      background: color, boxShadow: `0 0 8px ${color}`,
      animation: "pulse 1.5s ease-in-out infinite",
    }} />
  );
}

function StatCard({ label, value, sub, accent }) {
  return (
    <div style={{
      background: "rgba(255,255,255,0.03)", borderRadius: 10,
      padding: "14px 18px", border: "1px solid rgba(255,255,255,0.06)",
      minWidth: 0,
    }}>
      <div style={{ fontSize: 11, color: "#8a8a8a", textTransform: "uppercase", letterSpacing: 0.8 }}>{label}</div>
      <div style={{ fontSize: 26, fontWeight: 600, color: accent || "#e0e0e0", marginTop: 4, fontFamily: "'JetBrains Mono', 'Fira Code', monospace" }}>{value}</div>
      {sub && <div style={{ fontSize: 11, color: "#666", marginTop: 2 }}>{sub}</div>}
    </div>
  );
}

function RiskBadge({ level }) {
  const cfg = RISK_LEVELS[level] || RISK_LEVELS.low;
  return (
    <span style={{
      display: "inline-flex", alignItems: "center", gap: 5,
      padding: "3px 10px", borderRadius: 6, fontSize: 11, fontWeight: 600,
      background: cfg.bg, color: cfg.color, textTransform: "uppercase",
      letterSpacing: 0.5, border: `1px solid ${cfg.color}22`,
    }}>
      {cfg.pulse && <Pulse color={cfg.color} />}
      {level}
    </span>
  );
}

function CategoryTag({ cat }) {
  const cfg = ATTACK_CATEGORIES[cat];
  if (!cfg) return null;
  return (
    <span style={{
      display: "inline-block", padding: "2px 8px", borderRadius: 4, fontSize: 10,
      background: cfg.color + "18", color: cfg.color, fontWeight: 500,
      border: `1px solid ${cfg.color}25`,
    }}>{cfg.label}</span>
  );
}

function ThreatCard({ threat, isNew }) {
  const cfg = RISK_LEVELS[threat.level];
  return (
    <div style={{
      background: isNew ? cfg.bg : "rgba(255,255,255,0.02)",
      borderRadius: 10, padding: "14px 16px",
      border: `1px solid ${isNew ? cfg.color + "30" : "rgba(255,255,255,0.05)"}`,
      transition: "all 0.4s ease", marginBottom: 8,
      animation: isNew ? "slideIn 0.4s ease-out" : "none",
    }}>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
        <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
          <RiskBadge level={threat.level} />
          <span style={{ fontSize: 11, color: "#666", fontFamily: "monospace" }}>
            {threat.time.toLocaleTimeString()}
          </span>
        </div>
        <div style={{
          fontSize: 20, fontWeight: 700, fontFamily: "'JetBrains Mono', monospace",
          color: cfg.color,
        }}>
          {Math.round(threat.score * 100)}%
        </div>
      </div>
      <div style={{ fontSize: 13, color: "#c0c0c0", lineHeight: 1.5, marginBottom: 8 }}>
        {threat.desc}
      </div>
      <div style={{ display: "flex", gap: 6, flexWrap: "wrap", marginBottom: 8 }}>
        {threat.cats.map(c => <CategoryTag key={c} cat={c} />)}
      </div>
      <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
        <div style={{ display: "flex", gap: 16, fontSize: 11, color: "#777" }}>
          <span>TX: <span style={{ color: "#999", fontFamily: "monospace" }}>{threat.hash.slice(0,14)}...</span></span>
          <span>→ {threat.to}</span>
          <span>{threat.indicators} indicators</span>
          <span>{threat.latency}ms</span>
        </div>
        <div style={{
          fontSize: 10, fontWeight: 600, padding: "3px 8px", borderRadius: 4,
          background: threat.action === "PAUSE_CONTRACT" ? "rgba(226,75,74,0.15)" : "rgba(239,159,39,0.1)",
          color: threat.action === "PAUSE_CONTRACT" ? "#E24B4A" : "#EF9F27",
        }}>
          {threat.action}
        </div>
      </div>
    </div>
  );
}

// ── Main Dashboard ──

export default function ProtocolGuardianDashboard() {
  const [threats, setThreats] = useState([]);
  const [stats, setStats] = useState({ seen: 0, analyzed: 0, threats: 0, critical: 0, claude: 0, pauses: 0 });
  const [newThreatId, setNewThreatId] = useState(null);
  const [activeTab, setActiveTab] = useState("threats");
  const counterRef = useRef(0);
  const seenRef = useRef(0);

  useEffect(() => {
    const interval = setInterval(() => {
      seenRef.current += Math.floor(Math.random() * 40 + 15);
      const threat = generateThreat(counterRef.current++);
      setThreats(prev => [threat, ...prev].slice(0, 30));
      setNewThreatId(threat.id);
      setStats(s => ({
        seen: seenRef.current,
        analyzed: Math.floor(seenRef.current * 0.12),
        threats: s.threats + 1,
        critical: s.critical + (threat.level === "critical" ? 1 : 0),
        claude: s.claude + (threat.score >= 0.6 ? 1 : 0),
        pauses: s.pauses + (threat.action === "PAUSE_CONTRACT" ? 1 : 0),
      }));
      setTimeout(() => setNewThreatId(null), 1500);
    }, 4000);
    return () => clearInterval(interval);
  }, []);

  return (
    <div style={{
      background: "#0a0a0c", color: "#e0e0e0", minHeight: "100vh",
      fontFamily: "'Inter', -apple-system, sans-serif",
      padding: "0 0 40px",
    }}>
      <style>{`
        @keyframes pulse { 0%,100%{opacity:1} 50%{opacity:0.4} }
        @keyframes slideIn { from{opacity:0;transform:translateY(-8px)} to{opacity:1;transform:translateY(0)} }
        @keyframes scan { 0%{background-position:0% 50%} 50%{background-position:100% 50%} 100%{background-position:0% 50%} }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        ::-webkit-scrollbar { width: 4px; }
        ::-webkit-scrollbar-track { background: transparent; }
        ::-webkit-scrollbar-thumb { background: #333; border-radius: 4px; }
      `}</style>

      {/* ── Header ── */}
      <div style={{
        padding: "20px 32px", display: "flex", justifyContent: "space-between", alignItems: "center",
        borderBottom: "1px solid rgba(255,255,255,0.06)",
        background: "linear-gradient(180deg, rgba(226,75,74,0.03) 0%, transparent 100%)",
      }}>
        <div style={{ display: "flex", alignItems: "center", gap: 14 }}>
          <div style={{
            width: 36, height: 36, borderRadius: 10,
            background: "linear-gradient(135deg, #E24B4A 0%, #D85A30 100%)",
            display: "flex", alignItems: "center", justifyContent: "center",
            fontSize: 18, fontWeight: 700, color: "#fff",
          }}>G</div>
          <div>
            <div style={{ fontSize: 16, fontWeight: 600, letterSpacing: -0.3 }}>Protocol Guardian</div>
            <div style={{ fontSize: 11, color: "#666" }}>Autonomous AI DeFi Security Agent — v2.0</div>
          </div>
        </div>
        <div style={{ display: "flex", alignItems: "center", gap: 16 }}>
          <div style={{ display: "flex", alignItems: "center", gap: 6, fontSize: 12 }}>
            <Pulse color="#1D9E75" />
            <span style={{ color: "#1D9E75" }}>Mempool active</span>
          </div>
          <div style={{
            padding: "5px 12px", borderRadius: 6, fontSize: 11, fontWeight: 500,
            background: "rgba(55,138,221,0.1)", color: "#378ADD", border: "1px solid rgba(55,138,221,0.2)",
          }}>Sepolia Testnet</div>
        </div>
      </div>

      <div style={{ padding: "20px 32px" }}>
        {/* ── Stats Row ── */}
        <div style={{ display: "grid", gridTemplateColumns: "repeat(6, minmax(0, 1fr))", gap: 12, marginBottom: 24 }}>
          <StatCard label="Txs Scanned" value={stats.seen.toLocaleString()} sub="from mempool" />
          <StatCard label="Analyzed" value={stats.analyzed.toLocaleString()} sub="with calldata" />
          <StatCard label="Threats" value={stats.threats} accent="#EF9F27" sub="detected" />
          <StatCard label="Critical" value={stats.critical} accent="#E24B4A" sub="autonomous pause" />
          <StatCard label="Claude Calls" value={stats.claude} accent="#7F77DD" sub="AI assessments" />
          <StatCard label="Pauses" value={stats.pauses} accent="#E24B4A" sub="contracts paused" />
        </div>

        {/* ── Tab Navigation ── */}
        <div style={{ display: "flex", gap: 4, marginBottom: 20 }}>
          {[
            { id: "threats", label: "Live Threat Feed" },
            { id: "knowledge", label: "RAG Knowledge Base" },
            { id: "watchlist", label: "Watchlist" },
          ].map(tab => (
            <button key={tab.id} onClick={() => setActiveTab(tab.id)} style={{
              padding: "8px 20px", borderRadius: 8, fontSize: 13, fontWeight: 500,
              cursor: "pointer", border: "none", transition: "all 0.2s",
              background: activeTab === tab.id ? "rgba(255,255,255,0.08)" : "transparent",
              color: activeTab === tab.id ? "#e0e0e0" : "#666",
            }}>{tab.label}</button>
          ))}
        </div>

        {/* ── Live Threat Feed ── */}
        {activeTab === "threats" && (
          <div style={{ display: "grid", gridTemplateColumns: "1fr 320px", gap: 20 }}>
            <div>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
                <div style={{ fontSize: 14, fontWeight: 500, display: "flex", alignItems: "center", gap: 8 }}>
                  <Pulse color="#E24B4A" />
                  Pre-transaction threat detection
                </div>
                <div style={{ fontSize: 11, color: "#555" }}>Analyzing pending txs before block confirmation</div>
              </div>
              {threats.length === 0 ? (
                <div style={{ textAlign: "center", padding: 60, color: "#444", fontSize: 14 }}>
                  Waiting for mempool events...
                </div>
              ) : (
                threats.map(t => <ThreatCard key={t.id} threat={t} isNew={t.id === newThreatId} />)
              )}
            </div>

            {/* ── Sidebar: Threat Breakdown ── */}
            <div>
              <div style={{
                background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 16,
                border: "1px solid rgba(255,255,255,0.05)", marginBottom: 12,
              }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: "#999", marginBottom: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>
                  Detection breakdown
                </div>
                {Object.entries(ATTACK_CATEGORIES).map(([key, cfg]) => {
                  const count = threats.filter(t => t.cats.includes(key)).length;
                  const pct = threats.length > 0 ? (count / threats.length) * 100 : 0;
                  return (
                    <div key={key} style={{ marginBottom: 10 }}>
                      <div style={{ display: "flex", justifyContent: "space-between", fontSize: 12, marginBottom: 3 }}>
                        <span style={{ color: cfg.color }}>{cfg.icon} {cfg.label}</span>
                        <span style={{ color: "#666" }}>{count}</span>
                      </div>
                      <div style={{ height: 3, borderRadius: 2, background: "rgba(255,255,255,0.05)" }}>
                        <div style={{
                          height: "100%", borderRadius: 2, background: cfg.color,
                          width: `${Math.min(pct, 100)}%`, transition: "width 0.6s ease",
                        }} />
                      </div>
                    </div>
                  );
                })}
              </div>

              <div style={{
                background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 16,
                border: "1px solid rgba(255,255,255,0.05)",
              }}>
                <div style={{ fontSize: 12, fontWeight: 500, color: "#999", marginBottom: 12, textTransform: "uppercase", letterSpacing: 0.5 }}>
                  Risk distribution
                </div>
                {["critical", "high", "medium", "low"].map(level => {
                  const count = threats.filter(t => t.level === level).length;
                  const cfg = RISK_LEVELS[level];
                  return (
                    <div key={level} style={{ display: "flex", alignItems: "center", gap: 10, marginBottom: 8 }}>
                      <div style={{ width: 8, height: 8, borderRadius: "50%", background: cfg.color }} />
                      <span style={{ fontSize: 12, color: "#999", flex: 1, textTransform: "capitalize" }}>{level}</span>
                      <span style={{ fontSize: 14, fontWeight: 600, color: cfg.color, fontFamily: "monospace" }}>{count}</span>
                    </div>
                  );
                })}
              </div>
            </div>
          </div>
        )}

        {/* ── RAG Knowledge Base Tab ── */}
        {activeTab === "knowledge" && (
          <div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(4, minmax(0, 1fr))", gap: 12, marginBottom: 24 }}>
              <StatCard label="Historical Exploits" value={EXPLOIT_DB_STATS.total} accent="#7F77DD" sub="in knowledge base" />
              <StatCard label="Total Losses" value={EXPLOIT_DB_STATS.totalLoss} accent="#E24B4A" sub={EXPLOIT_DB_STATS.dateRange} />
              <StatCard label="Chains Covered" value={EXPLOIT_DB_STATS.chains} accent="#378ADD" sub="EVM + Solana" />
              <StatCard label="Attack Categories" value={EXPLOIT_DB_STATS.categories.length} accent="#1D9E75" sub="indexed for RAG" />
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "1fr 1fr", gap: 16 }}>
              <div style={{
                background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 20,
                border: "1px solid rgba(255,255,255,0.05)",
              }}>
                <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 16 }}>Exploit categories by loss</div>
                {EXPLOIT_DB_STATS.categories.map((cat, i) => (
                  <div key={cat.name} style={{ marginBottom: 14 }}>
                    <div style={{ display: "flex", justifyContent: "space-between", fontSize: 13, marginBottom: 4 }}>
                      <span style={{ color: "#c0c0c0" }}>{cat.name}</span>
                      <span style={{ color: "#999", fontFamily: "monospace" }}>{cat.loss} ({cat.count})</span>
                    </div>
                    <div style={{ height: 6, borderRadius: 3, background: "rgba(255,255,255,0.04)" }}>
                      <div style={{
                        height: "100%", borderRadius: 3, transition: "width 0.8s ease",
                        background: ["#E24B4A", "#EF9F27", "#D4537E", "#7F77DD", "#378ADD", "#1D9E75"][i],
                        width: `${Math.min((parseInt(cat.loss.replace(/[^0-9]/g, "")) / 2150) * 100, 100)}%`,
                      }} />
                    </div>
                  </div>
                ))}
              </div>

              <div style={{
                background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 20,
                border: "1px solid rgba(255,255,255,0.05)",
              }}>
                <div style={{ fontSize: 14, fontWeight: 500, marginBottom: 16 }}>How RAG context injection works</div>
                {[
                  { step: "1", label: "Mempool detects threat", desc: "Function selectors matched against 32+ patterns", color: "#E24B4A" },
                  { step: "2", label: "RAG queries exploit DB", desc: "Finds historical parallels by category + selector", color: "#EF9F27" },
                  { step: "3", label: "Context injected to Claude", desc: "Historical exploit details added to prompt", color: "#7F77DD" },
                  { step: "4", label: "Claude risk assessment", desc: "AI compares current tx to historical patterns", color: "#378ADD" },
                  { step: "5", label: "Autonomous action", desc: "pause() / alert based on confidence score", color: "#1D9E75" },
                ].map(item => (
                  <div key={item.step} style={{
                    display: "flex", gap: 12, alignItems: "flex-start", marginBottom: 14,
                  }}>
                    <div style={{
                      width: 24, height: 24, borderRadius: 6, flexShrink: 0,
                      background: item.color + "18", color: item.color,
                      display: "flex", alignItems: "center", justifyContent: "center",
                      fontSize: 12, fontWeight: 700, border: `1px solid ${item.color}30`,
                    }}>{item.step}</div>
                    <div>
                      <div style={{ fontSize: 13, fontWeight: 500, color: "#c0c0c0" }}>{item.label}</div>
                      <div style={{ fontSize: 11, color: "#666", marginTop: 2 }}>{item.desc}</div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ── Watchlist Tab ── */}
        {activeTab === "watchlist" && (
          <div>
            <div style={{ fontSize: 13, color: "#666", marginBottom: 16 }}>
              Monitoring {WATCHED_PROTOCOLS.filter(p => p.status === "active").length} active contracts. Pending contracts will activate when mainnet keys are configured.
            </div>
            <div style={{ display: "grid", gridTemplateColumns: "repeat(3, minmax(0, 1fr))", gap: 12 }}>
              {WATCHED_PROTOCOLS.map(p => (
                <div key={p.name} style={{
                  background: "rgba(255,255,255,0.02)", borderRadius: 10, padding: 16,
                  border: `1px solid ${p.status === "active" ? "rgba(29,158,117,0.2)" : "rgba(255,255,255,0.05)"}`,
                }}>
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 8 }}>
                    <span style={{ fontSize: 14, fontWeight: 500 }}>{p.name}</span>
                    <div style={{
                      display: "flex", alignItems: "center", gap: 5, fontSize: 11,
                      color: p.status === "active" ? "#1D9E75" : "#666",
                    }}>
                      {p.status === "active" && <Pulse color="#1D9E75" />}
                      {p.status}
                    </div>
                  </div>
                  <div style={{ fontSize: 12, fontFamily: "monospace", color: "#777" }}>{p.address}</div>
                  <div style={{
                    fontSize: 11, marginTop: 6, padding: "2px 8px", borderRadius: 4,
                    display: "inline-block",
                    background: p.chain === "Sepolia" ? "rgba(127,119,221,0.1)" : "rgba(55,138,221,0.08)",
                    color: p.chain === "Sepolia" ? "#7F77DD" : "#378ADD",
                  }}>{p.chain}</div>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* ── Footer ── */}
        <div style={{
          marginTop: 32, paddingTop: 16, borderTop: "1px solid rgba(255,255,255,0.04)",
          display: "flex", justifyContent: "space-between", fontSize: 11, color: "#444",
        }}>
          <span>Protocol Guardian v2 — ETHGlobal Open Agents 2026</span>
          <span>Sepolia: MockLendingPool 0x8456...630E • ProtocolGuardian 0x2344...12fE</span>
        </div>
      </div>
    </div>
  );
}
