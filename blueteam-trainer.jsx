import React, { useState, useCallback, useRef, useEffect, useMemo } from "react";

// ---------------------------------------------------------------------------
// Color palette and tactic metadata
// ---------------------------------------------------------------------------

const C = {
  bg: '#0d1117', surface: '#161b22', elevated: '#1c2128', border: '#21262d',
  accent: '#00d97e', accentDim: 'rgba(0,217,126,0.12)', accentText: '#00b865',
  text: '#e6edf3', textSec: '#8b949e', textMuted: '#3d444d',
  red: '#f85149', amber: '#d29922', blue: '#388bfd', purple: '#a371f7',
  orange: '#f0883e', pink: '#f778ba', teal: '#56d4c8', yellow: '#e3b341',
  green: '#00d97e',
};

const TACTIC_META = {
  'TA0043': { name: 'Reconnaissance',        color: '#79c0ff' },
  'TA0042': { name: 'Resource Development',  color: '#a371f7' },
  'TA0001': { name: 'Initial Access',        color: '#f85149' },
  'TA0002': { name: 'Execution',             color: '#f0883e' },
  'TA0003': { name: 'Persistence',           color: '#d29922' },
  'TA0004': { name: 'Privilege Escalation',  color: '#7ee787' },
  'TA0005': { name: 'Defense Evasion',       color: '#388bfd' },
  'TA0006': { name: 'Credential Access',     color: '#a371f7' },
  'TA0007': { name: 'Discovery',             color: '#79c0ff' },
  'TA0008': { name: 'Lateral Movement',      color: '#f778ba' },
  'TA0009': { name: 'Collection',            color: '#56d4c8' },
  'TA0011': { name: 'Command & Control',     color: '#ff7b72' },
  'TA0010': { name: 'Exfiltration',          color: '#bd93f9' },
  'TA0040': { name: 'Impact',                color: '#ff5555' },
};

// Order tactics in the way they appear in the MITRE ATT&CK matrix
const TACTIC_ORDER = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
  'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
  'TA0010', 'TA0040',
];

// ---------------------------------------------------------------------------
// Data loading — pulled from the embedded payload
// ---------------------------------------------------------------------------

function loadTechniques() {
  const payload = (typeof window !== 'undefined' && window.__BTT_TECHNIQUES__) || null;
  if (!payload || !Array.isArray(payload.techniques)) {
    return { techniques: [], meta: { merged_total: 0, curated_count: 0 } };
  }
  return {
    techniques: payload.techniques,
    meta: payload._meta || {},
  };
}

// ---------------------------------------------------------------------------
// URL hash routing
// ---------------------------------------------------------------------------

function parseHash() {
  const raw = (typeof window !== 'undefined' ? window.location.hash : '') || '';
  const stripped = raw.replace(/^#\/?/, '');
  if (!stripped) return { view: 'tactics' };
  const parts = stripped.split('/');
  if (parts[0] === 'tactic' && parts[1]) return { view: 'techniques', tacticId: parts[1] };
  if (parts[0] === 'technique' && parts[1]) return { view: 'detail', techniqueId: parts[1] };
  if (parts[0] === 'scenarios') return { view: 'scenarios' };
  if (parts[0] === 'session') return { view: 'session' };
  return { view: 'tactics' };
}

function navigateTo(path) {
  if (typeof window !== 'undefined') {
    window.location.hash = path;
  }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function CodeBlock({ code, lang }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  const langColors = { splunk: C.amber, vql: C.teal, powershell: C.blue };
  return (
    <div style={{ background: C.bg, border: `1px solid ${C.border}`, borderRadius: 6, marginBottom: 10, overflow: 'hidden' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '6px 12px', borderBottom: `1px solid ${C.border}`, background: C.elevated }}>
        <span style={{ fontSize: 11, fontFamily: 'monospace', color: langColors[lang] || C.textSec, fontWeight: 600, letterSpacing: 1, textTransform: 'uppercase' }}>{lang}</span>
        <button onClick={copy} style={{ background: 'none', border: `1px solid ${C.border}`, color: copied ? C.accent : C.textSec, cursor: 'pointer', fontSize: 11, padding: '2px 10px', borderRadius: 4, fontFamily: 'monospace', transition: 'color 0.2s' }}>
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
      <pre style={{ margin: 0, padding: '12px 14px', fontSize: 12, lineHeight: 1.65, color: C.text, fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', monospace", overflowX: 'auto', whiteSpace: 'pre' }}>
        {code}
      </pre>
    </div>
  );
}

function TacticBadge({ tacticId, small }) {
  const t = TACTIC_META[tacticId];
  if (!t) return null;
  return (
    <span style={{ display: 'inline-block', background: `${t.color}18`, color: t.color, border: `1px solid ${t.color}40`, borderRadius: 4, padding: small ? '1px 6px' : '2px 8px', fontSize: small ? 10 : 11, fontFamily: 'monospace', fontWeight: 600, whiteSpace: 'nowrap', letterSpacing: 0.5 }}>
      {t.name}
    </span>
  );
}

function ConnectivityBadge({ test, small }) {
  let color, label, title;
  if (test.offlineCapable) {
    color = C.green; label = '○ OFFLINE';
    title = 'Works on a fully isolated victim';
  } else if (test.prereqStage) {
    color = C.amber; label = '◐ STAGED';
    title = 'Works offline if Check Prereqs run first while online, then snapshotted';
  } else {
    color = C.red; label = '● ONLINE';
    title = 'Requires internet at runtime';
  }
  return (
    <span title={title} style={{ display: 'inline-block', background: `${color}18`, color, border: `1px solid ${color}40`, borderRadius: 4, padding: small ? '1px 6px' : '2px 8px', fontSize: small ? 9 : 10, fontFamily: 'monospace', fontWeight: 600, whiteSpace: 'nowrap', letterSpacing: 0.5 }}>
      {label}
    </span>
  );
}

function PlatformBadge({ platforms }) {
  if (!platforms || !platforms.length) return null;
  // Show first 3 platforms; if more, show "+N"
  const display = platforms.slice(0, 3);
  const extra = platforms.length - display.length;
  const platformColors = {
    windows: C.blue, linux: C.amber, macos: C.textSec,
    containers: C.teal, 'iaas': C.purple, 'office-365': C.orange,
    'azure-ad': C.purple, 'google-workspace': C.amber,
  };
  return (
    <span style={{ display: 'inline-flex', gap: 4, alignItems: 'center' }}>
      {display.map(p => (
        <span key={p} title={p} style={{
          fontSize: 9, fontFamily: 'monospace', color: platformColors[p] || C.textSec,
          padding: '1px 5px', border: `1px solid ${(platformColors[p] || C.textSec)}40`,
          borderRadius: 3, background: `${platformColors[p] || C.textSec}10`,
          letterSpacing: 0.3, textTransform: 'lowercase',
        }}>{p}</span>
      ))}
      {extra > 0 && <span style={{ fontSize: 9, color: C.textMuted, fontFamily: 'monospace' }}>+{extra}</span>}
    </span>
  );
}

function StatusDot({ status }) {
  const map = { pending: C.textMuted, running: C.amber, complete: C.accent, failed: C.red };
  return <span style={{ display: 'inline-block', width: 8, height: 8, borderRadius: '50%', background: map[status] || C.textMuted, flexShrink: 0, marginRight: 6 }} />;
}

// ---------------------------------------------------------------------------
// Main component
// ---------------------------------------------------------------------------

export default function BlueTeamTrainer() {
  // Data — loaded once from the embedded payload
  const dataRef = useRef(loadTechniques());
  const TECHNIQUES = dataRef.current.techniques;
  const DATA_META = dataRef.current.meta;

  // URL routing state
  const [route, setRoute] = useState(parseHash());
  useEffect(() => {
    const onHashChange = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // Filters and search
  const [hideTacticsWithoutCuration, setHideTacticsWithoutCuration] = useState(false);
  const [tacticListSort, setTacticListSort] = useState('curated-first'); // curated-first | id
  const [search, setSearch] = useState('');
  const [connectivityFilter, setConnectivityFilter] = useState('all');
  const [platformFilter, setPlatformFilter] = useState('windows'); // default to windows since that's what the platform supports
  const [curatedOnly, setCuratedOnly] = useState(false);

  // Detonation / session log / scenarios — preserved from original
  const [sessionLog, setSessionLog] = useState([]);
  const [detonatingId, setDetonatingId] = useState(null);
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [apiBase, setApiBase] = useState('http://localhost:8000');
  const [mockMode, setMockMode] = useState(true);
  const [showSettings, setShowSettings] = useState(false);

  // Scenario builder
  const [scenarioChain, setScenarioChain] = useState([]);
  const [chainRunning, setChainRunning] = useState(false);
  const [scenarioName, setScenarioName] = useState('Unnamed Scenario');
  const [savedScenarios, setSavedScenarios] = useState([]);
  const chainRef = useRef(scenarioChain);
  chainRef.current = scenarioChain;

  // Detail view tab state
  const [detailTab, setDetailTab] = useState('tests');
  const [huntPackTab, setHuntPackTab] = useState('splunk');

  // -------------------------------------------------------------------------
  // Derived data — tactic counts, technique lookup
  // -------------------------------------------------------------------------

  const techniqueIndex = useMemo(() => {
    const map = {};
    TECHNIQUES.forEach(t => { map[t.id] = t; });
    return map;
  }, [TECHNIQUES]);

  // For each tactic, how many techniques map to it (including multi-tactic ones)?
  const tacticCounts = useMemo(() => {
    const counts = {};
    TACTIC_ORDER.forEach(tid => { counts[tid] = { total: 0, curated: 0 }; });
    TECHNIQUES.forEach(t => {
      const tactics = t.tactics && t.tactics.length ? t.tactics : [t.tactic];
      tactics.forEach(tid => {
        if (counts[tid]) {
          counts[tid].total += 1;
          if (t.curated) counts[tid].curated += 1;
        }
      });
    });
    return counts;
  }, [TECHNIQUES]);

  // -------------------------------------------------------------------------
  // Detonation handler — same logic as original, slightly tightened
  // -------------------------------------------------------------------------

  const handleDetonate = useCallback(async (technique, atomicTest) => {
    setDetonatingId(atomicTest.id);
    const start = Date.now();
    if (mockMode) {
      await new Promise(r => setTimeout(r, 1400 + Math.random() * 800));
      const success = Math.random() > 0.12;
      const entry = {
        id: uid(), timestamp: new Date(), technique, atomicTest,
        status: success ? 'success' : 'failed',
        duration: Date.now() - start,
        stdout: success ? 'Mock execution OK' : '',
        stderr: success ? '' : 'Mock failure for UI testing',
      };
      setSessionLog(prev => [entry, ...prev]);
      setDetonatingId(null);
    } else {
      try {
        const res = await fetch(`${apiBase}/detonate`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ technique_id: technique.id, test_id: atomicTest.id })
        });
        const data = await res.json();
        const entry = {
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: data.success ? 'success' : 'failed',
          duration: Date.now() - start,
          stdout: data.stdout || '', stderr: data.stderr || '',
          httpStatus: res.status,
        };
        setSessionLog(prev => [entry, ...prev]);
      } catch (err) {
        const entry = {
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: 'failed', duration: Date.now() - start,
          stdout: '', stderr: `Network error: ${err.message}`, httpStatus: 0,
        };
        setSessionLog(prev => [entry, ...prev]);
      }
      setDetonatingId(null);
    }
  }, [apiBase, mockMode]);

  const handleCheckPrereqs = useCallback(async (technique, atomicTest) => {
    setDetonatingId(atomicTest.id);
    const start = Date.now();
    if (mockMode) {
      await new Promise(r => setTimeout(r, 800));
      const entry = {
        id: uid(), timestamp: new Date(), technique, atomicTest,
        status: 'success', kind: 'prereq',
        duration: Date.now() - start,
        stdout: 'Mock prereq check OK', stderr: '',
      };
      setSessionLog(prev => [entry, ...prev]);
    } else {
      try {
        const res = await fetch(`${apiBase}/check_prereqs`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ technique_id: technique.id, test_id: atomicTest.id })
        });
        const data = await res.json();
        const entry = {
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: data.success ? 'success' : 'failed', kind: 'prereq',
          duration: Date.now() - start,
          stdout: data.stdout || '', stderr: data.stderr || '',
          httpStatus: res.status,
        };
        setSessionLog(prev => [entry, ...prev]);
      } catch (err) {
        const entry = {
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: 'failed', kind: 'prereq', duration: Date.now() - start,
          stdout: '', stderr: `Network error: ${err.message}`, httpStatus: 0,
        };
        setSessionLog(prev => [entry, ...prev]);
      }
    }
    setDetonatingId(null);
  }, [apiBase, mockMode]);

  // -------------------------------------------------------------------------
  // Scenario chain handlers — preserved from original
  // -------------------------------------------------------------------------

  const addToChain = (technique, atomicTest) => {
    const item = {
      id: uid(), technique, selectedTest: atomicTest,
      status: 'pending', stdout: '', stderr: '',
    };
    setScenarioChain(prev => [...prev, item]);
  };

  const removeFromChain = (itemId) => {
    setScenarioChain(prev => prev.filter(c => c.id !== itemId));
  };

  const moveChainItem = (itemId, direction) => {
    setScenarioChain(prev => {
      const idx = prev.findIndex(c => c.id === itemId);
      if (idx < 0) return prev;
      const newIdx = idx + direction;
      if (newIdx < 0 || newIdx >= prev.length) return prev;
      const copy = [...prev];
      [copy[idx], copy[newIdx]] = [copy[newIdx], copy[idx]];
      return copy;
    });
  };

  const resetChain = () => {
    setScenarioChain(prev => prev.map(c => ({ ...c, status: 'pending', stdout: '', stderr: '' })));
  };

  const runChain = async () => {
    if (chainRunning) return;
    setChainRunning(true);
    for (let i = 0; i < chainRef.current.length; i++) {
      const item = chainRef.current[i];
      setScenarioChain(prev => prev.map(c => c.id === item.id ? { ...c, status: 'running' } : c));
      const start = Date.now();
      let result;
      if (mockMode) {
        await new Promise(r => setTimeout(r, 1100 + Math.random() * 800));
        const success = Math.random() > 0.15;
        result = { success, stdout: success ? 'Mock OK' : '', stderr: success ? '' : 'Mock failure', duration: Date.now() - start };
      } else {
        try {
          const res = await fetch(`${apiBase}/detonate`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ technique_id: item.technique.id, test_id: item.selectedTest.id })
          });
          const data = await res.json();
          result = { success: data.success, stdout: data.stdout || '', stderr: data.stderr || '', duration: Date.now() - start };
        } catch (err) {
          result = { success: false, stdout: '', stderr: `Network error: ${err.message}`, duration: Date.now() - start };
        }
      }
      setScenarioChain(prev => prev.map(c => c.id === item.id ? {
        ...c, status: result.success ? 'complete' : 'failed',
        stdout: result.stdout, stderr: result.stderr, duration: result.duration,
      } : c));
      // Append to session log
      const logEntry = {
        id: uid(), timestamp: new Date(), technique: item.technique, atomicTest: item.selectedTest,
        status: result.success ? 'success' : 'failed', duration: result.duration,
        stdout: result.stdout, stderr: result.stderr, scenario: scenarioName,
      };
      setSessionLog(prev => [logEntry, ...prev]);
      if (!result.success) break;  // stop chain on failure
    }
    setChainRunning(false);
  };

  const saveScenario = () => {
    if (!scenarioChain.length) return;
    const scenario = {
      id: uid(),
      name: scenarioName,
      chain: scenarioChain.map(i => ({ technique: i.technique, selectedTest: i.selectedTest })),
      createdAt: new Date(),
    };
    setSavedScenarios(prev => [scenario, ...prev]);
  };

  const loadScenario = (scenario) => {
    setScenarioName(scenario.name);
    setScenarioChain(scenario.chain.map(i => ({ ...i, id: uid(), status: 'pending', stdout: '', stderr: '' })));
  };

  // -------------------------------------------------------------------------
  // Render — header, then route-dispatched view
  // -------------------------------------------------------------------------

  // Empty data state (build hasn't run yet)
  if (!TECHNIQUES.length) {
    return <EmptyDataView />;
  }

  return (
    <div style={{ height: '100vh', width: '100vw', display: 'flex', flexDirection: 'column', background: C.bg, color: C.text, fontFamily: "'JetBrains Mono', 'Fira Code', 'Cascadia Code', ui-monospace, monospace", overflow: 'hidden' }}>
      <Header
        route={route}
        meta={DATA_META}
        sessionLogCount={sessionLog.length}
        scenarioChainCount={scenarioChain.length}
        showSettings={showSettings}
        setShowSettings={setShowSettings}
      />

      {showSettings && (
        <SettingsPanel
          apiBase={apiBase} setApiBase={setApiBase}
          mockMode={mockMode} setMockMode={setMockMode}
          onClose={() => setShowSettings(false)}
        />
      )}

      <div style={{ flex: 1, overflow: 'hidden', display: 'flex' }}>
        {route.view === 'tactics' && (
          <TacticsView
            techniques={TECHNIQUES}
            tacticCounts={tacticCounts}
            hideTacticsWithoutCuration={hideTacticsWithoutCuration}
            setHideTacticsWithoutCuration={setHideTacticsWithoutCuration}
            search={search}
            setSearch={setSearch}
          />
        )}

        {route.view === 'techniques' && (
          <TechniquesView
            techniques={TECHNIQUES}
            tacticId={route.tacticId}
            tacticCounts={tacticCounts}
            sortMode={tacticListSort}
            setSortMode={setTacticListSort}
            curatedOnly={curatedOnly}
            setCuratedOnly={setCuratedOnly}
            connectivityFilter={connectivityFilter}
            setConnectivityFilter={setConnectivityFilter}
            platformFilter={platformFilter}
            setPlatformFilter={setPlatformFilter}
            search={search}
            setSearch={setSearch}
          />
        )}

        {route.view === 'detail' && (
          <DetailView
            technique={techniqueIndex[route.techniqueId]}
            techniqueId={route.techniqueId}
            detailTab={detailTab}
            setDetailTab={setDetailTab}
            huntPackTab={huntPackTab}
            setHuntPackTab={setHuntPackTab}
            detonatingId={detonatingId}
            handleDetonate={handleDetonate}
            handleCheckPrereqs={handleCheckPrereqs}
            addToChain={addToChain}
            scenarioChain={scenarioChain}
          />
        )}

        {route.view === 'scenarios' && (
          <ScenariosView
            scenarioChain={scenarioChain}
            scenarioName={scenarioName}
            setScenarioName={setScenarioName}
            chainRunning={chainRunning}
            runChain={runChain}
            resetChain={resetChain}
            removeFromChain={removeFromChain}
            moveChainItem={moveChainItem}
            setScenarioChain={setScenarioChain}
            saveScenario={saveScenario}
            savedScenarios={savedScenarios}
            loadScenario={loadScenario}
          />
        )}

        {route.view === 'session' && (
          <SessionLogView
            sessionLog={sessionLog}
            setSessionLog={setSessionLog}
            expandedLogId={expandedLogId}
            setExpandedLogId={setExpandedLogId}
          />
        )}
      </div>
    </div>
  );
}

// ===========================================================================
// Header
// ===========================================================================

function Header({ route, meta, sessionLogCount, scenarioChainCount, showSettings, setShowSettings }) {
  const navItem = (path, label, count, active) => (
    <button
      key={path}
      onClick={() => navigateTo(path)}
      style={{
        background: active ? `${C.accent}15` : 'none',
        border: `1px solid ${active ? `${C.accent}50` : C.border}`,
        color: active ? C.accent : C.textSec,
        padding: '6px 14px', borderRadius: 5, cursor: 'pointer',
        fontSize: 11, fontWeight: 600, letterSpacing: 0.8,
        textTransform: 'uppercase',
        display: 'inline-flex', alignItems: 'center', gap: 6,
      }}
    >
      {label}
      {count > 0 && (
        <span style={{
          background: active ? C.accent : C.textMuted, color: '#000',
          borderRadius: 10, fontSize: 9, padding: '1px 6px', fontWeight: 700,
        }}>{count}</span>
      )}
    </button>
  );

  const isTactics = route.view === 'tactics';
  const isTechniques = route.view === 'techniques';
  const isDetail = route.view === 'detail';
  const isScenarios = route.view === 'scenarios';
  const isSession = route.view === 'session';

  return (
    <div style={{ display: 'flex', alignItems: 'center', padding: '10px 18px', borderBottom: `1px solid ${C.border}`, background: C.surface, flexShrink: 0 }}>
      <button onClick={() => navigateTo('/')} style={{ background: 'none', border: 'none', cursor: 'pointer', padding: 0, marginRight: 18 }}>
        <div style={{ fontSize: 13, fontWeight: 700, color: C.accent, letterSpacing: 1 }}>BLUE TEAM TRAINER</div>
        <div style={{ fontSize: 9, color: C.textMuted, letterSpacing: 0.5, marginTop: 2 }}>
          {meta.merged_total || 0} techniques · {meta.curated_count || 0} curated
        </div>
      </button>

      <div style={{ display: 'flex', gap: 6, marginLeft: 12 }}>
        {navItem('/', 'Tactics', 0, isTactics || isTechniques || isDetail)}
        {navItem('/scenarios', 'Scenarios', scenarioChainCount, isScenarios)}
        {navItem('/session', 'Session log', sessionLogCount, isSession)}
      </div>

      <div style={{ marginLeft: 'auto', display: 'flex', gap: 8, alignItems: 'center' }}>
        <button onClick={() => setShowSettings(!showSettings)} style={{
          background: showSettings ? `${C.accent}15` : 'none',
          border: `1px solid ${showSettings ? `${C.accent}50` : C.border}`,
          color: showSettings ? C.accent : C.textSec,
          padding: '6px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 11, fontWeight: 600,
        }}>⚙ Settings</button>
      </div>
    </div>
  );
}

function SettingsPanel({ apiBase, setApiBase, mockMode, setMockMode, onClose }) {
  return (
    <div style={{ background: C.elevated, borderBottom: `1px solid ${C.border}`, padding: '14px 18px', flexShrink: 0 }}>
      <div style={{ display: 'flex', gap: 24, alignItems: 'center', flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <label style={{ fontSize: 11, color: C.textSec, fontWeight: 600 }}>API base:</label>
          <input value={apiBase} onChange={e => setApiBase(e.target.value)} style={{ background: C.bg, border: `1px solid ${C.border}`, color: C.text, padding: '4px 10px', fontSize: 12, borderRadius: 4, fontFamily: 'monospace', width: 240 }} />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <label style={{ fontSize: 11, color: C.textSec, fontWeight: 600 }}>Mode:</label>
          <button onClick={() => setMockMode(!mockMode)} style={{
            background: mockMode ? `${C.amber}20` : `${C.accent}20`,
            border: `1px solid ${mockMode ? C.amber : C.accent}60`,
            color: mockMode ? C.amber : C.accent,
            padding: '4px 12px', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontWeight: 600,
          }}>{mockMode ? '⚠ Mock mode' : '● Live mode'}</button>
        </div>
        <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: `1px solid ${C.border}`, color: C.textSec, padding: '4px 12px', borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>✕ Close</button>
      </div>
    </div>
  );
}

// ===========================================================================
// View 1: Tactics grid (landing)
// ===========================================================================

function TacticsView({ techniques, tacticCounts, hideTacticsWithoutCuration, setHideTacticsWithoutCuration, search, setSearch }) {
  // Search across all techniques globally
  const searchResults = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return null;
    return techniques.filter(t =>
      t.id.toLowerCase().includes(q) ||
      t.name.toLowerCase().includes(q)
    ).slice(0, 25);
  }, [search, techniques]);

  const visibleTactics = TACTIC_ORDER.filter(tid => {
    if (hideTacticsWithoutCuration && tacticCounts[tid] && tacticCounts[tid].curated === 0) return false;
    return true;
  });

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '24px 32px' }}>
      <div style={{ marginBottom: 20 }}>
        <h2 style={{ margin: 0, fontSize: 18, fontWeight: 600, color: C.text, letterSpacing: 0.3 }}>Pick a tactic to begin</h2>
        <p style={{ margin: '6px 0 0', fontSize: 12, color: C.textSec, lineHeight: 1.5 }}>
          Each card represents one of the 14 MITRE ATT&amp;CK Enterprise tactics.
          Click through to see the techniques mapped to it.
        </p>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 240 }}>
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search by technique ID or name (e.g. T1566 or Spearphishing)"
            style={{ width: '100%', background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '8px 14px', borderRadius: 5, fontSize: 12, fontFamily: 'inherit' }}
          />
        </div>
        <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 11, color: C.textSec, fontWeight: 600 }}>
          <input type="checkbox" checked={hideTacticsWithoutCuration} onChange={e => setHideTacticsWithoutCuration(e.target.checked)} />
          Hide tactics without curated content
        </label>
      </div>

      {searchResults && (
        <div style={{ marginBottom: 24, padding: 14, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 8 }}>
          <div style={{ fontSize: 11, color: C.textSec, marginBottom: 10, fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase' }}>
            Search results — {searchResults.length} match{searchResults.length !== 1 ? 'es' : ''}
          </div>
          {searchResults.length === 0 ? (
            <div style={{ fontSize: 12, color: C.textMuted, padding: 8 }}>No matches.</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {searchResults.map(t => (
                <button key={t.id} onClick={() => navigateTo(`/technique/${t.id}`)} style={{
                  background: 'none', border: `1px solid ${C.border}`, color: C.text,
                  textAlign: 'left', padding: '8px 12px', borderRadius: 5, cursor: 'pointer',
                  fontSize: 12, display: 'flex', alignItems: 'center', gap: 10,
                  fontFamily: 'inherit',
                }}>
                  <span style={{ color: t.curated ? C.accent : C.textMuted, fontFamily: 'monospace', minWidth: 16 }}>{t.curated ? '★' : ' '}</span>
                  <span style={{ color: C.textMuted, fontFamily: 'monospace', fontSize: 11, minWidth: 90 }}>{t.id}</span>
                  <span style={{ flex: 1 }}>{t.name}</span>
                  <TacticBadge tacticId={t.tactic} small />
                </button>
              ))}
            </div>
          )}
        </div>
      )}

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(220px, 1fr))', gap: 14 }}>
        {visibleTactics.map(tid => {
          const meta = TACTIC_META[tid];
          const counts = tacticCounts[tid] || { total: 0, curated: 0 };
          if (!meta) return null;
          const empty = counts.total === 0;
          return (
            <button
              key={tid}
              onClick={() => !empty && navigateTo(`/tactic/${tid}`)}
              disabled={empty}
              style={{
                background: empty ? C.bg : C.surface,
                border: `1px solid ${empty ? C.border : `${meta.color}30`}`,
                borderLeft: `3px solid ${meta.color}`,
                borderRadius: 7,
                padding: '14px 16px',
                cursor: empty ? 'not-allowed' : 'pointer',
                textAlign: 'left',
                color: C.text,
                display: 'flex', flexDirection: 'column', gap: 6,
                opacity: empty ? 0.4 : 1,
                fontFamily: 'inherit',
                transition: 'all 0.15s',
              }}
              onMouseEnter={e => { if (!empty) e.currentTarget.style.background = C.elevated; }}
              onMouseLeave={e => { if (!empty) e.currentTarget.style.background = C.surface; }}
            >
              <div style={{ fontSize: 10, color: meta.color, fontFamily: 'monospace', fontWeight: 700, letterSpacing: 0.8 }}>{tid}</div>
              <div style={{ fontSize: 14, fontWeight: 600, color: C.text }}>{meta.name}</div>
              <div style={{ fontSize: 11, color: C.textSec, marginTop: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>
                <span>{counts.total} technique{counts.total !== 1 ? 's' : ''}</span>
                {counts.curated > 0 && (
                  <span style={{ color: C.accent }}>★ {counts.curated} curated</span>
                )}
              </div>
            </button>
          );
        })}
      </div>
    </div>
  );
}

// ===========================================================================
// View 2: Techniques list within a tactic
// ===========================================================================

function TechniquesView({
  techniques, tacticId, tacticCounts, sortMode, setSortMode,
  curatedOnly, setCuratedOnly, connectivityFilter, setConnectivityFilter,
  platformFilter, setPlatformFilter, search, setSearch,
}) {
  const meta = TACTIC_META[tacticId];

  const filtered = useMemo(() => {
    let result = techniques.filter(t => {
      const tactics = t.tactics && t.tactics.length ? t.tactics : [t.tactic];
      if (!tactics.includes(tacticId)) return false;
      if (curatedOnly && !t.curated) return false;
      const q = search.toLowerCase().trim();
      if (q && !t.id.toLowerCase().includes(q) && !t.name.toLowerCase().includes(q)) return false;
      // Connectivity filter operates on whether ANY of the technique's tests match
      if (connectivityFilter !== 'all') {
        const hasMatch = (t.atomicTests || []).some(at => {
          if (connectivityFilter === 'offline') return at.offlineCapable;
          if (connectivityFilter === 'staged') return !at.offlineCapable && at.prereqStage;
          if (connectivityFilter === 'online') return !at.offlineCapable && !at.prereqStage;
          return true;
        });
        if (!hasMatch) return false;
      }
      // Platform filter operates on whether ANY of the technique's tests target it
      if (platformFilter !== 'all') {
        const hasMatch = (t.atomicTests || []).some(at =>
          (at.supportedPlatforms || []).includes(platformFilter)
        );
        if (!hasMatch) return false;
      }
      return true;
    });

    if (sortMode === 'curated-first') {
      result.sort((a, b) => {
        if (a.curated !== b.curated) return a.curated ? -1 : 1;
        return a.id.localeCompare(b.id);
      });
    } else {
      result.sort((a, b) => a.id.localeCompare(b.id));
    }
    return result;
  }, [techniques, tacticId, sortMode, curatedOnly, connectivityFilter, platformFilter, search]);

  if (!meta) {
    return (
      <div style={{ flex: 1, padding: 32, color: C.textSec, fontSize: 13 }}>
        Unknown tactic: {tacticId}.
        <button onClick={() => navigateTo('/')} style={{ marginLeft: 12, background: 'none', border: `1px solid ${C.border}`, color: C.textSec, padding: '4px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>← Back to tactics</button>
      </div>
    );
  }

  const counts = tacticCounts[tacticId] || { total: 0, curated: 0 };

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 32px' }}>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: C.textSec, marginBottom: 14, fontFamily: 'monospace' }}>
        <button onClick={() => navigateTo('/')} style={{ background: 'none', border: 'none', color: C.textSec, cursor: 'pointer', padding: 0, fontSize: 11, fontFamily: 'inherit' }}>← Tactics</button>
        <span style={{ color: C.textMuted }}>/</span>
        <span>{tacticId}</span>
      </div>

      {/* Tactic header */}
      <div style={{ marginBottom: 18, paddingBottom: 14, borderBottom: `1px solid ${C.border}` }}>
        <div style={{ fontSize: 11, color: meta.color, fontFamily: 'monospace', fontWeight: 700, letterSpacing: 0.8 }}>{tacticId}</div>
        <h2 style={{ margin: '4px 0 6px', fontSize: 22, fontWeight: 600, color: C.text }}>{meta.name}</h2>
        <div style={{ fontSize: 12, color: C.textSec }}>
          {counts.total} technique{counts.total !== 1 ? 's' : ''}
          {counts.curated > 0 && <span style={{ color: C.accent, marginLeft: 8 }}>· ★ {counts.curated} curated</span>}
        </div>
      </div>

      {/* Filter bar */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 16, flexWrap: 'wrap', padding: '10px 0', borderBottom: `1px solid ${C.border}` }}>
        <input
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter…"
          style={{ flex: 1, minWidth: 160, background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '6px 12px', borderRadius: 5, fontSize: 12, fontFamily: 'inherit' }}
        />

        <FilterPills
          label=""
          options={[
            ['curated-first', '★ Curated first'],
            ['id', 'By ID'],
          ]}
          value={sortMode}
          setValue={setSortMode}
        />

        <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 11, color: C.textSec, fontWeight: 600 }}>
          <input type="checkbox" checked={curatedOnly} onChange={e => setCuratedOnly(e.target.checked)} />
          Curated only
        </label>

        <FilterPills
          label="Net"
          options={[
            ['all', 'All'],
            ['offline', '○ Offline'],
            ['staged', '◐ Staged'],
            ['online', '● Online'],
          ]}
          value={connectivityFilter}
          setValue={setConnectivityFilter}
        />

        <FilterPills
          label="Platform"
          options={[
            ['all', 'All'],
            ['windows', 'Windows'],
            ['linux', 'Linux'],
            ['macos', 'macOS'],
          ]}
          value={platformFilter}
          setValue={setPlatformFilter}
        />
      </div>

      {/* Result count */}
      <div style={{ fontSize: 11, color: C.textMuted, marginBottom: 8 }}>
        Showing {filtered.length} technique{filtered.length !== 1 ? 's' : ''}
      </div>

      {/* Techniques list */}
      {filtered.length === 0 ? (
        <div style={{ padding: 32, textAlign: 'center', color: C.textMuted, fontSize: 12, border: `1px dashed ${C.border}`, borderRadius: 7 }}>
          No techniques match the current filters.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {filtered.map(t => (
            <TechniqueRow key={t.id} technique={t} />
          ))}
        </div>
      )}
    </div>
  );
}

function FilterPills({ label, options, value, setValue }) {
  return (
    <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
      {label && <span style={{ fontSize: 10, color: C.textMuted, fontWeight: 600, letterSpacing: 0.5, textTransform: 'uppercase', marginRight: 2 }}>{label}</span>}
      {options.map(([k, l]) => (
        <button
          key={k}
          onClick={() => setValue(k)}
          style={{
            background: value === k ? `${C.accent}15` : 'none',
            border: `1px solid ${value === k ? `${C.accent}50` : C.border}`,
            color: value === k ? C.accent : C.textSec,
            padding: '4px 10px', borderRadius: 4, cursor: 'pointer', fontSize: 11, fontWeight: 600, fontFamily: 'inherit',
          }}
        >{l}</button>
      ))}
    </div>
  );
}

function TechniqueRow({ technique }) {
  const testCount = (technique.atomicTests || []).length;
  // Aggregate connectivity flags: if any test is offline, show offline badge etc.
  const allOffline = testCount > 0 && (technique.atomicTests || []).every(t => t.offlineCapable);
  const anyStaged = (technique.atomicTests || []).some(t => !t.offlineCapable && t.prereqStage);
  const allOnline = testCount > 0 && (technique.atomicTests || []).every(t => !t.offlineCapable && !t.prereqStage);
  let aggregateBadge = null;
  if (allOffline) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: true, prereqStage: false }} small />;
  else if (allOnline) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: false, prereqStage: false }} small />;
  else if (anyStaged) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: false, prereqStage: true }} small />;

  // Aggregate platforms
  const allPlatforms = new Set();
  (technique.atomicTests || []).forEach(t => (t.supportedPlatforms || []).forEach(p => allPlatforms.add(p)));

  return (
    <button onClick={() => navigateTo(`/technique/${technique.id}`)} style={{
      background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6,
      padding: '10px 14px', cursor: 'pointer', textAlign: 'left',
      display: 'flex', alignItems: 'center', gap: 14,
      color: C.text, fontFamily: 'inherit',
      transition: 'all 0.15s',
    }}
      onMouseEnter={e => { e.currentTarget.style.borderColor = `${C.accent}50`; e.currentTarget.style.background = C.elevated; }}
      onMouseLeave={e => { e.currentTarget.style.borderColor = C.border; e.currentTarget.style.background = C.surface; }}
    >
      <span style={{ color: technique.curated ? C.accent : C.textMuted, fontSize: 14, minWidth: 14 }}>
        {technique.curated ? '★' : ' '}
      </span>
      <span style={{ fontFamily: 'monospace', fontSize: 11, color: C.textMuted, minWidth: 90 }}>{technique.id}</span>
      <span style={{ flex: 1, fontSize: 13, fontWeight: 500 }}>{technique.name}</span>
      <span style={{ fontSize: 11, color: C.textMuted, fontFamily: 'monospace' }}>
        {testCount} test{testCount !== 1 ? 's' : ''}
      </span>
      <PlatformBadge platforms={[...allPlatforms]} />
      {aggregateBadge}
      <span style={{ color: C.textMuted, fontSize: 13 }}>›</span>
    </button>
  );
}

// ===========================================================================
// View 3: Technique detail
// ===========================================================================

function DetailView({
  technique, techniqueId, detailTab, setDetailTab,
  huntPackTab, setHuntPackTab,
  detonatingId, handleDetonate, handleCheckPrereqs,
  addToChain, scenarioChain,
}) {
  if (!technique) {
    return (
      <div style={{ flex: 1, padding: 32, color: C.textSec, fontSize: 13 }}>
        <div style={{ marginBottom: 12 }}>Technique <code style={{ background: C.surface, padding: '2px 8px', borderRadius: 4 }}>{techniqueId}</code> not found in the library.</div>
        <button onClick={() => navigateTo('/')} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.textSec, padding: '6px 14px', borderRadius: 5, cursor: 'pointer', fontSize: 12 }}>← Back to tactics</button>
      </div>
    );
  }

  const tactics = technique.tactics && technique.tactics.length ? technique.tactics : [technique.tactic];
  const primaryTactic = tactics[0];

  const inChain = (testId) => scenarioChain.some(c => c.selectedTest && c.selectedTest.id === testId);

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 32px' }}>
      {/* Breadcrumb */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11, color: C.textSec, marginBottom: 14, fontFamily: 'monospace' }}>
        <button onClick={() => navigateTo('/')} style={{ background: 'none', border: 'none', color: C.textSec, cursor: 'pointer', padding: 0, fontSize: 11, fontFamily: 'inherit' }}>Tactics</button>
        <span style={{ color: C.textMuted }}>/</span>
        <button onClick={() => navigateTo(`/tactic/${primaryTactic}`)} style={{ background: 'none', border: 'none', color: C.textSec, cursor: 'pointer', padding: 0, fontSize: 11, fontFamily: 'inherit' }}>
          {TACTIC_META[primaryTactic]?.name || primaryTactic}
        </button>
        <span style={{ color: C.textMuted }}>/</span>
        <span>{technique.id}</span>
      </div>

      {/* Header */}
      <div style={{ marginBottom: 18, paddingBottom: 14, borderBottom: `1px solid ${C.border}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          {technique.curated && <span style={{ color: C.accent, fontSize: 16 }}>★</span>}
          <span style={{ fontFamily: 'monospace', fontSize: 11, color: C.textMuted, fontWeight: 700, letterSpacing: 0.5 }}>{technique.id}</span>
          {tactics.map(t => <TacticBadge key={t} tacticId={t} small />)}
        </div>
        <h2 style={{ margin: '4px 0 8px', fontSize: 22, fontWeight: 600, color: C.text }}>{technique.name}</h2>
        <div style={{ fontSize: 12, color: C.textSec }}>
          {(technique.atomicTests || []).length} atomic test{(technique.atomicTests || []).length !== 1 ? 's' : ''}
          {!technique.curated && (
            <span style={{ marginLeft: 12, fontSize: 11, color: C.amber }}>
              No curated hunt pack yet — <a href="https://github.com/Incogn1toBro/BlueTeam-Trainer/blob/main/CONTRIBUTING.md" target="_blank" rel="noreferrer" style={{ color: C.amber }}>contributions welcome</a>
            </span>
          )}
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', gap: 4, marginBottom: 14, borderBottom: `1px solid ${C.border}` }}>
        {[
          ['tests', `Atomic tests (${(technique.atomicTests || []).length})`],
          ['hunt', technique.curated ? 'Hunt pack' : 'Hunt pack (not curated)'],
        ].map(([k, l]) => (
          <button
            key={k}
            onClick={() => setDetailTab(k)}
            disabled={k === 'hunt' && !technique.curated}
            style={{
              background: 'none',
              border: 'none',
              color: detailTab === k ? C.accent : (k === 'hunt' && !technique.curated ? C.textMuted : C.textSec),
              padding: '8px 14px',
              borderBottom: `2px solid ${detailTab === k ? C.accent : 'transparent'}`,
              cursor: (k === 'hunt' && !technique.curated) ? 'not-allowed' : 'pointer',
              fontSize: 12, fontWeight: 600,
              fontFamily: 'inherit',
              marginBottom: -1,
            }}
          >
            {l}
          </button>
        ))}
      </div>

      {detailTab === 'tests' && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {(technique.atomicTests || []).map(test => (
            <AtomicTestCard
              key={test.id}
              technique={technique}
              test={test}
              detonatingId={detonatingId}
              handleDetonate={handleDetonate}
              handleCheckPrereqs={handleCheckPrereqs}
              addToChain={addToChain}
              alreadyInChain={inChain(test.id)}
            />
          ))}
        </div>
      )}

      {detailTab === 'hunt' && technique.curated && technique.huntPack && (
        <HuntPackPanel huntPack={technique.huntPack} huntPackTab={huntPackTab} setHuntPackTab={setHuntPackTab} />
      )}

      {detailTab === 'hunt' && (!technique.curated || !technique.huntPack) && (
        <div style={{ padding: 22, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, color: C.textSec, fontSize: 12, lineHeight: 1.6 }}>
          <div style={{ color: C.text, fontWeight: 600, marginBottom: 8 }}>No curated hunt pack yet</div>
          This technique exists in the upstream Atomic Red Team library, but no analyst-facing hunt queries have been written for it yet.
          You can still detonate the atomic tests — open the “Atomic tests” tab — but you will need to write your own SPL / VQL / PowerShell queries to hunt the activity.
          <div style={{ marginTop: 12 }}>
            Contributions welcome — see <a href="https://github.com/Incogn1toBro/BlueTeam-Trainer/blob/main/CONTRIBUTING.md" target="_blank" rel="noreferrer" style={{ color: C.accent }}>CONTRIBUTING.md</a> for how to add a hunt pack.
          </div>
        </div>
      )}
    </div>
  );
}

function AtomicTestCard({ technique, test, detonatingId, handleDetonate, handleCheckPrereqs, addToChain, alreadyInChain }) {
  const isDetonating = detonatingId === test.id;
  const supportedOnWindows = (test.supportedPlatforms || []).includes('windows');
  return (
    <div style={{ background: C.surface, border: `1px solid ${C.border}`, borderRadius: 7, padding: 14 }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6, flexWrap: 'wrap' }}>
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: C.textMuted, fontWeight: 600 }}>{test.id}</span>
        <ConnectivityBadge test={test} small />
        <PlatformBadge platforms={test.supportedPlatforms} />
        {test.hasPrereqs && (
          <span title="Has dependencies that must be satisfied" style={{ display: 'inline-block', background: `${C.purple}18`, color: C.purple, border: `1px solid ${C.purple}40`, borderRadius: 4, padding: '1px 6px', fontSize: 9, fontFamily: 'monospace', fontWeight: 600 }}>
            PREREQ
          </span>
        )}
      </div>
      <div style={{ fontSize: 13, fontWeight: 600, color: C.text, marginBottom: 6 }}>{test.name}</div>
      <div style={{ fontSize: 12, color: C.textSec, lineHeight: 1.5, marginBottom: 12 }}>{test.description}</div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        <button
          onClick={() => handleDetonate(technique, test)}
          disabled={isDetonating || !supportedOnWindows}
          title={!supportedOnWindows ? 'This test does not support Windows; the platform cannot detonate it.' : ''}
          style={{
            background: isDetonating ? `${C.amber}20` : (!supportedOnWindows ? C.bg : `${C.red}15`),
            border: `1px solid ${isDetonating ? `${C.amber}60` : (!supportedOnWindows ? C.border : `${C.red}50`)}`,
            color: isDetonating ? C.amber : (!supportedOnWindows ? C.textMuted : C.red),
            padding: '6px 14px', borderRadius: 5, cursor: (isDetonating || !supportedOnWindows) ? 'not-allowed' : 'pointer',
            fontSize: 11, fontWeight: 700, letterSpacing: 0.8, fontFamily: 'inherit',
          }}
        >{isDetonating ? '⟳ Detonating…' : '⚡ Detonate'}</button>
        {test.hasPrereqs && (
          <button
            onClick={() => handleCheckPrereqs(technique, test)}
            disabled={isDetonating || !supportedOnWindows}
            style={{
              background: 'none', border: `1px solid ${C.border}`,
              color: !supportedOnWindows ? C.textMuted : C.textSec,
              padding: '6px 14px', borderRadius: 5,
              cursor: (isDetonating || !supportedOnWindows) ? 'not-allowed' : 'pointer',
              fontSize: 11, fontWeight: 600, fontFamily: 'inherit',
            }}
          >⚙ Check prereqs</button>
        )}
        <button
          onClick={() => addToChain(technique, test)}
          disabled={alreadyInChain || !supportedOnWindows}
          style={{
            background: 'none', border: `1px solid ${C.border}`,
            color: alreadyInChain ? C.textMuted : (!supportedOnWindows ? C.textMuted : C.textSec),
            padding: '6px 14px', borderRadius: 5,
            cursor: (alreadyInChain || !supportedOnWindows) ? 'not-allowed' : 'pointer',
            fontSize: 11, fontWeight: 600, fontFamily: 'inherit',
          }}
        >{alreadyInChain ? '✓ In chain' : '+ Add to chain'}</button>
      </div>
    </div>
  );
}

function HuntPackPanel({ huntPack, huntPackTab, setHuntPackTab }) {
  const tabs = [
    ['splunk', 'Splunk SPL', huntPack.splunk || []],
    ['vql', 'Velociraptor VQL', huntPack.vql || []],
    ['powershell', 'PowerShell', huntPack.powershell || []],
  ];
  const active = tabs.find(t => t[0] === huntPackTab) || tabs[0];
  return (
    <div>
      <div style={{ display: 'flex', gap: 4, marginBottom: 12 }}>
        {tabs.map(([k, l, arr]) => (
          <button key={k} onClick={() => setHuntPackTab(k)} style={{
            background: huntPackTab === k ? `${C.accent}15` : 'none',
            border: `1px solid ${huntPackTab === k ? `${C.accent}50` : C.border}`,
            color: huntPackTab === k ? C.accent : C.textSec,
            padding: '6px 12px', borderRadius: 5, cursor: 'pointer',
            fontSize: 11, fontWeight: 600, fontFamily: 'inherit',
          }}>{l} {arr.length > 0 && <span style={{ marginLeft: 4, fontSize: 9, color: C.textMuted }}>{arr.length}</span>}</button>
        ))}
      </div>
      {active[2].length === 0 ? (
        <div style={{ padding: 16, color: C.textMuted, fontSize: 12, border: `1px dashed ${C.border}`, borderRadius: 6 }}>
          No {active[1]} queries curated for this technique.
        </div>
      ) : (
        active[2].map((code, i) => <CodeBlock key={i} code={code} lang={active[0]} />)
      )}
    </div>
  );
}

// ===========================================================================
// View 4: Scenarios — preserved with light tweaks for the new layout
// ===========================================================================

function ScenariosView({
  scenarioChain, scenarioName, setScenarioName,
  chainRunning, runChain, resetChain,
  removeFromChain, moveChainItem, setScenarioChain,
  saveScenario, savedScenarios, loadScenario,
}) {
  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 32px' }}>
      <div style={{ marginBottom: 18, paddingBottom: 14, borderBottom: `1px solid ${C.border}` }}>
        <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: C.text }}>Scenarios</h2>
        <p style={{ margin: '6px 0 0', fontSize: 12, color: C.textSec, lineHeight: 1.5 }}>
          Chain multiple atomic tests together to simulate a full attack path.
          Open a technique, click <code style={{ background: C.surface, padding: '1px 6px', borderRadius: 3 }}>+ Add to chain</code>, then come back here to run the sequence.
        </p>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <input
          value={scenarioName}
          onChange={e => setScenarioName(e.target.value)}
          placeholder="Name this scenario"
          style={{ flex: 1, maxWidth: 360, background: C.elevated, border: `1px solid ${C.border}`, color: C.text, padding: '6px 12px', borderRadius: 5, fontSize: 12, fontFamily: 'inherit' }}
        />
        <span style={{ fontSize: 11, color: C.textMuted }}>{scenarioChain.length} step{scenarioChain.length !== 1 ? 's' : ''}</span>
      </div>

      {scenarioChain.length === 0 ? (
        <div style={{ padding: 32, textAlign: 'center', color: C.textMuted, fontSize: 12, border: `1px dashed ${C.border}`, borderRadius: 7 }}>
          Empty chain. Open a technique and click <strong>+ Add to chain</strong>.
        </div>
      ) : (
        <div>
          {scenarioChain.map((item, idx) => (
            <div key={item.id} style={{ display: 'flex', gap: 10, marginBottom: 10 }}>
              <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', paddingTop: 6 }}>
                <StatusDot status={item.status} />
                {idx < scenarioChain.length - 1 && <div style={{ width: 1, flex: 1, background: C.border, minHeight: 16, margin: '4px 0' }} />}
              </div>
              <div style={{
                flex: 1,
                background: C.surface,
                border: `1px solid ${item.status === 'running' ? `${C.amber}50` : item.status === 'complete' ? `${C.accent}30` : item.status === 'failed' ? `${C.red}30` : C.border}`,
                borderRadius: 7, padding: 12,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 6 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <span style={{ fontFamily: 'monospace', fontSize: 11, color: C.textMuted }}>#{idx + 1}</span>
                    <button onClick={() => navigateTo(`/technique/${item.technique.id}`)} style={{ background: 'none', border: 'none', color: C.text, cursor: 'pointer', padding: 0, fontSize: 13, fontWeight: 500, fontFamily: 'inherit' }}>
                      {item.technique.id} — {item.technique.name}
                    </button>
                  </div>
                  <div style={{ display: 'flex', gap: 4 }}>
                    <button onClick={() => moveChainItem(item.id, -1)} disabled={idx === 0} style={{ background: 'none', border: `1px solid ${C.border}`, color: idx === 0 ? C.textMuted : C.textSec, padding: '2px 7px', borderRadius: 4, cursor: idx === 0 ? 'not-allowed' : 'pointer', fontSize: 11 }}>↑</button>
                    <button onClick={() => moveChainItem(item.id, 1)} disabled={idx === scenarioChain.length - 1} style={{ background: 'none', border: `1px solid ${C.border}`, color: idx === scenarioChain.length - 1 ? C.textMuted : C.textSec, padding: '2px 7px', borderRadius: 4, cursor: idx === scenarioChain.length - 1 ? 'not-allowed' : 'pointer', fontSize: 11 }}>↓</button>
                    <button onClick={() => removeFromChain(item.id)} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.red, padding: '2px 7px', borderRadius: 4, cursor: 'pointer', fontSize: 11 }}>✕</button>
                  </div>
                </div>
                <div style={{ fontSize: 11, color: C.textSec }}>{item.selectedTest.name}</div>
                {item.stderr && (
                  <pre style={{ marginTop: 8, padding: 8, background: C.bg, border: `1px solid ${C.red}30`, borderRadius: 4, fontSize: 11, color: C.red, fontFamily: 'monospace', whiteSpace: 'pre-wrap' }}>{item.stderr}</pre>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {scenarioChain.length > 0 && (
        <div style={{ display: 'flex', gap: 8, marginTop: 16 }}>
          <button onClick={runChain} disabled={chainRunning} style={{
            flex: 1,
            background: chainRunning ? `${C.red}10` : `${C.red}20`,
            border: `1px solid ${C.red}60`, color: chainRunning ? C.textSec : C.red,
            padding: '10px 0', borderRadius: 5, cursor: chainRunning ? 'not-allowed' : 'pointer',
            fontSize: 12, fontWeight: 700, letterSpacing: 1, fontFamily: 'inherit',
          }}>
            {chainRunning ? '⟳ RUNNING CHAIN…' : '⚡ RUN CHAIN'}
          </button>
          <button onClick={resetChain} disabled={chainRunning} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.textSec, padding: '10px 14px', borderRadius: 5, cursor: chainRunning ? 'not-allowed' : 'pointer', fontSize: 12, fontFamily: 'inherit' }}>Reset</button>
          <button onClick={saveScenario} disabled={chainRunning} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.accent, padding: '10px 14px', borderRadius: 5, cursor: chainRunning ? 'not-allowed' : 'pointer', fontSize: 12, fontFamily: 'inherit' }}>Save</button>
          <button onClick={() => setScenarioChain([])} disabled={chainRunning} style={{ background: 'none', border: `1px solid ${C.border}`, color: C.red, padding: '10px 14px', borderRadius: 5, cursor: chainRunning ? 'not-allowed' : 'pointer', fontSize: 12, fontFamily: 'inherit' }}>Clear</button>
        </div>
      )}

      {savedScenarios.length > 0 && (
        <div style={{ marginTop: 32 }}>
          <h3 style={{ fontSize: 13, color: C.textSec, fontWeight: 600, marginBottom: 10, letterSpacing: 0.5, textTransform: 'uppercase' }}>Saved scenarios</h3>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {savedScenarios.map(s => (
              <button key={s.id} onClick={() => loadScenario(s)} style={{ background: C.surface, border: `1px solid ${C.border}`, color: C.text, padding: '8px 12px', borderRadius: 5, cursor: 'pointer', textAlign: 'left', display: 'flex', alignItems: 'center', gap: 12, fontFamily: 'inherit' }}>
                <span style={{ fontSize: 12, fontWeight: 600 }}>{s.name}</span>
                <span style={{ fontSize: 11, color: C.textMuted }}>{s.chain.length} step{s.chain.length !== 1 ? 's' : ''}</span>
              </button>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// View 5: Session log
// ===========================================================================

function SessionLogView({ sessionLog, setSessionLog, expandedLogId, setExpandedLogId }) {
  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '20px 32px' }}>
      <div style={{ marginBottom: 18, paddingBottom: 14, borderBottom: `1px solid ${C.border}`, display: 'flex', alignItems: 'center' }}>
        <div>
          <h2 style={{ margin: 0, fontSize: 20, fontWeight: 600, color: C.text }}>Session log</h2>
          <p style={{ margin: '6px 0 0', fontSize: 12, color: C.textSec }}>{sessionLog.length} entr{sessionLog.length === 1 ? 'y' : 'ies'} this session</p>
        </div>
        {sessionLog.length > 0 && (
          <button onClick={() => setSessionLog([])} style={{ marginLeft: 'auto', background: 'none', border: `1px solid ${C.border}`, color: C.red, padding: '6px 12px', borderRadius: 5, cursor: 'pointer', fontSize: 11, fontFamily: 'inherit' }}>Clear log</button>
        )}
      </div>

      {sessionLog.length === 0 ? (
        <div style={{ padding: 32, textAlign: 'center', color: C.textMuted, fontSize: 12, border: `1px dashed ${C.border}`, borderRadius: 7 }}>
          Nothing detonated yet.
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {sessionLog.map(entry => {
            const expanded = expandedLogId === entry.id;
            const hasOutput = (entry.stdout && entry.stdout.trim()) || (entry.stderr && entry.stderr.trim());
            return (
              <div key={entry.id} style={{ background: C.surface, border: `1px solid ${entry.status === 'success' ? `${C.accent}30` : `${C.red}30`}`, borderRadius: 6, overflow: 'hidden' }}>
                <button
                  onClick={() => hasOutput && setExpandedLogId(expanded ? null : entry.id)}
                  style={{
                    width: '100%', background: 'none', border: 'none',
                    padding: '10px 14px', textAlign: 'left', cursor: hasOutput ? 'pointer' : 'default',
                    color: C.text, fontFamily: 'inherit', display: 'flex', alignItems: 'center', gap: 12,
                  }}
                >
                  <span style={{ color: C.textMuted, fontSize: 11, fontFamily: 'monospace', minWidth: 70 }}>
                    {entry.timestamp.toLocaleTimeString()}
                  </span>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: C.textMuted, minWidth: 90 }}>{entry.technique.id}</span>
                  <span style={{ flex: 1, fontSize: 12 }}>
                    <span style={{ color: C.text }}>{entry.technique.name}</span>
                    <span style={{ color: C.textMuted, marginLeft: 8 }}>· {entry.atomicTest.name}</span>
                  </span>
                  {entry.kind === 'prereq' && (
                    <span style={{ background: `${C.purple}20`, color: C.purple, border: `1px solid ${C.purple}50`, padding: '1px 7px', borderRadius: 3, fontSize: 10, fontWeight: 600 }}>PREREQ</span>
                  )}
                  <span style={{ fontSize: 11, color: C.textMuted, fontFamily: 'monospace' }}>{entry.duration}ms</span>
                  <span style={{ color: entry.status === 'success' ? C.accent : C.red, fontWeight: 700, fontSize: 11, letterSpacing: 0.5 }}>
                    {entry.status === 'success' ? '✓ SUCCESS' : '✕ FAILED'}
                  </span>
                  {hasOutput && <span style={{ color: C.textMuted }}>{expanded ? '▾' : '▸'}</span>}
                </button>
                {expanded && hasOutput && (
                  <div style={{ borderTop: `1px solid ${C.border}`, background: C.bg, padding: 12 }}>
                    {entry.stdout && entry.stdout.trim() && (
                      <div style={{ marginBottom: 10 }}>
                        <div style={{ fontSize: 10, color: C.accent, fontWeight: 600, letterSpacing: 1, marginBottom: 4 }}>STDOUT</div>
                        <pre style={{ margin: 0, padding: 10, background: C.surface, border: `1px solid ${C.border}`, borderRadius: 4, fontSize: 11, color: C.text, fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: 280, overflow: 'auto' }}>{entry.stdout}</pre>
                      </div>
                    )}
                    {entry.stderr && entry.stderr.trim() && (
                      <div>
                        <div style={{ fontSize: 10, color: C.red, fontWeight: 600, letterSpacing: 1, marginBottom: 4 }}>STDERR</div>
                        <pre style={{ margin: 0, padding: 10, background: C.surface, border: `1px solid ${C.red}30`, borderRadius: 4, fontSize: 11, color: C.red, fontFamily: 'monospace', whiteSpace: 'pre-wrap', maxHeight: 280, overflow: 'auto' }}>{entry.stderr}</pre>
                      </div>
                    )}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}

// ===========================================================================
// Empty data view — shown when no techniques.json embedded yet
// ===========================================================================

function EmptyDataView() {
  return (
    <div style={{ height: '100vh', display: 'flex', alignItems: 'center', justifyContent: 'center', background: C.bg, color: C.text, fontFamily: "'JetBrains Mono', monospace" }}>
      <div style={{ maxWidth: 540, padding: 32, textAlign: 'center' }}>
        <div style={{ fontSize: 14, color: C.amber, fontWeight: 700, letterSpacing: 1, marginBottom: 12 }}>NO TECHNIQUE LIBRARY EMBEDDED</div>
        <div style={{ fontSize: 13, color: C.textSec, lineHeight: 1.7, marginBottom: 18 }}>
          The HTML was built without <code style={{ background: C.surface, padding: '1px 6px', borderRadius: 3 }}>data/techniques.json</code>.
          Run the build pipeline:
        </div>
        <pre style={{ margin: 0, padding: '14px 18px', background: C.surface, border: `1px solid ${C.border}`, borderRadius: 6, fontSize: 12, color: C.text, textAlign: 'left' }}>{`./build.sh`}</pre>
        <div style={{ fontSize: 12, color: C.textMuted, marginTop: 14, lineHeight: 1.6 }}>
          This pulls Atomic Red Team upstream, merges your curation overlay,
          and rebuilds the HTML with the technique library embedded.
        </div>
      </div>
    </div>
  );
}
