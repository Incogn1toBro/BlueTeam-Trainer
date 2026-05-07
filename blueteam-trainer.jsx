import React, { useState, useCallback, useRef, useEffect, useMemo } from "react";

// ---------------------------------------------------------------------------
// Tactic metadata
// ---------------------------------------------------------------------------

const TACTIC_META = {
  'TA0043': { name: 'Reconnaissance',        var: '--tactic-recon' },
  'TA0042': { name: 'Resource Development',  var: '--tactic-resource' },
  'TA0001': { name: 'Initial Access',        var: '--tactic-initial' },
  'TA0002': { name: 'Execution',             var: '--tactic-execution' },
  'TA0003': { name: 'Persistence',           var: '--tactic-persistence' },
  'TA0004': { name: 'Privilege Escalation',  var: '--tactic-privesc' },
  'TA0005': { name: 'Defense Evasion',       var: '--tactic-defense' },
  'TA0006': { name: 'Credential Access',     var: '--tactic-credential' },
  'TA0007': { name: 'Discovery',             var: '--tactic-discovery' },
  'TA0008': { name: 'Lateral Movement',      var: '--tactic-lateral' },
  'TA0009': { name: 'Collection',            var: '--tactic-collection' },
  'TA0011': { name: 'Command & Control',     var: '--tactic-c2' },
  'TA0010': { name: 'Exfiltration',          var: '--tactic-exfil' },
  'TA0040': { name: 'Impact',                var: '--tactic-impact' },
};

const TACTIC_ORDER = [
  'TA0043', 'TA0042', 'TA0001', 'TA0002', 'TA0003', 'TA0004',
  'TA0005', 'TA0006', 'TA0007', 'TA0008', 'TA0009', 'TA0011',
  'TA0010', 'TA0040',
];

// ---------------------------------------------------------------------------
// Data loading
// ---------------------------------------------------------------------------

function loadTechniques() {
  const payload = (typeof window !== 'undefined' && window.__BTT_TECHNIQUES__) || null;
  if (!payload || !Array.isArray(payload.techniques)) {
    return { techniques: [], meta: { merged_total: 0, curated_count: 0 } };
  }
  return { techniques: payload.techniques, meta: payload._meta || {} };
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
  if (typeof window !== 'undefined') window.location.hash = path;
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function uid() {
  return Math.random().toString(36).slice(2, 10);
}

function tacticColorStyle(tacticId) {
  const meta = TACTIC_META[tacticId];
  if (!meta) return {};
  return { '--tactic-color': `var(${meta.var})` };
}

// ---------------------------------------------------------------------------
// Reusable components
// ---------------------------------------------------------------------------

function CodeBlock({ code, lang }) {
  const [copied, setCopied] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(code).catch(() => {});
    setCopied(true);
    setTimeout(() => setCopied(false), 1800);
  };
  return (
    <div className="code-block">
      <div className="code-block-head">
        <span className={`code-block-lang ${lang}`}>{lang}</span>
        <button onClick={copy} className={`code-block-copy ${copied ? 'copied' : ''}`}>
          {copied ? '✓ copied' : 'copy'}
        </button>
      </div>
      <pre>{code}</pre>
    </div>
  );
}

function TacticBadge({ tacticId }) {
  const t = TACTIC_META[tacticId];
  if (!t) return null;
  return (
    <span
      className="badge tactic"
      style={{ color: `var(${t.var})`, borderColor: `var(${t.var})`, background: 'transparent' }}
    >
      {t.name}
    </span>
  );
}

function ConnectivityBadge({ test }) {
  let cls, label, title;
  if (test.offlineCapable) {
    cls = 'connectivity-offline'; label = '○ OFFLINE';
    title = 'Works on a fully isolated victim';
  } else if (test.prereqStage) {
    cls = 'connectivity-staged'; label = '◐ STAGED';
    title = 'Works offline if Check Prereqs run first while online, then snapshotted';
  } else {
    cls = 'connectivity-online'; label = '● ONLINE';
    title = 'Requires internet at runtime';
  }
  return <span title={title} className={`badge ${cls}`}>{label}</span>;
}

function PlatformBadge({ platforms }) {
  if (!platforms || !platforms.length) return null;
  const display = platforms.slice(0, 3);
  const extra = platforms.length - display.length;
  return (
    <span className="platform-row">
      {display.map(p => (
        <span key={p} title={p} className="badge platform">{p}</span>
      ))}
      {extra > 0 && <span className="badge platform-extra">+{extra}</span>}
    </span>
  );
}

function StatusDot({ status }) {
  return <span className={`dot ${status || 'pending'}`} />;
}

// ===========================================================================
// Main component
// ===========================================================================

export default function BlueTeamTrainer() {
  const dataRef = useRef(loadTechniques());
  const TECHNIQUES = dataRef.current.techniques;
  const DATA_META = dataRef.current.meta;

  const [route, setRoute] = useState(parseHash());
  useEffect(() => {
    const onHashChange = () => setRoute(parseHash());
    window.addEventListener('hashchange', onHashChange);
    return () => window.removeEventListener('hashchange', onHashChange);
  }, []);

  // Filters and search
  const [hideTacticsWithoutCuration, setHideTacticsWithoutCuration] = useState(false);
  const [tacticListSort, setTacticListSort] = useState('curated-first');
  const [search, setSearch] = useState('');
  const [connectivityFilter, setConnectivityFilter] = useState('all');
  const [platformFilter, setPlatformFilter] = useState('windows');
  const [curatedOnly, setCuratedOnly] = useState(false);

  // Detonation / session log
  const [sessionLog, setSessionLog] = useState([]);
  const [detonatingId, setDetonatingId] = useState(null);
  const [expandedLogId, setExpandedLogId] = useState(null);
  const [apiBase, setApiBase] = useState('http://localhost:8000');
  const [mockMode, setMockMode] = useState(true);
  const [showSettings, setShowSettings] = useState(false);

  // Scenarios
  const [scenarioChain, setScenarioChain] = useState([]);
  const [chainRunning, setChainRunning] = useState(false);
  const [scenarioName, setScenarioName] = useState('Unnamed Scenario');
  const [savedScenarios, setSavedScenarios] = useState([]);
  const chainRef = useRef(scenarioChain);
  chainRef.current = scenarioChain;

  // Detail view tabs
  const [detailTab, setDetailTab] = useState('tests');
  const [huntPackTab, setHuntPackTab] = useState('splunk');

  const techniqueIndex = useMemo(() => {
    const map = {};
    TECHNIQUES.forEach(t => { map[t.id] = t; });
    return map;
  }, [TECHNIQUES]);

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
  // Detonation
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
      setSessionLog(prev => [{
        id: uid(), timestamp: new Date(), technique, atomicTest,
        status: 'success', kind: 'prereq', duration: Date.now() - start,
        stdout: 'Mock prereq check OK', stderr: '',
      }, ...prev]);
    } else {
      try {
        const res = await fetch(`${apiBase}/check_prereqs`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ technique_id: technique.id, test_id: atomicTest.id })
        });
        const data = await res.json();
        setSessionLog(prev => [{
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: data.success ? 'success' : 'failed', kind: 'prereq',
          duration: Date.now() - start,
          stdout: data.stdout || '', stderr: data.stderr || '',
          httpStatus: res.status,
        }, ...prev]);
      } catch (err) {
        setSessionLog(prev => [{
          id: uid(), timestamp: new Date(), technique, atomicTest,
          status: 'failed', kind: 'prereq', duration: Date.now() - start,
          stdout: '', stderr: `Network error: ${err.message}`, httpStatus: 0,
        }, ...prev]);
      }
    }
    setDetonatingId(null);
  }, [apiBase, mockMode]);

  // Scenario handlers
  const addToChain = (technique, atomicTest) => {
    setScenarioChain(prev => [...prev, {
      id: uid(), technique, selectedTest: atomicTest,
      status: 'pending', stdout: '', stderr: '',
    }]);
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
      setSessionLog(prev => [{
        id: uid(), timestamp: new Date(), technique: item.technique, atomicTest: item.selectedTest,
        status: result.success ? 'success' : 'failed', duration: result.duration,
        stdout: result.stdout, stderr: result.stderr, scenario: scenarioName,
      }, ...prev]);
      if (!result.success) break;
    }
    setChainRunning(false);
  };
  const saveScenario = () => {
    if (!scenarioChain.length) return;
    setSavedScenarios(prev => [{
      id: uid(), name: scenarioName,
      chain: scenarioChain.map(i => ({ technique: i.technique, selectedTest: i.selectedTest })),
      createdAt: new Date(),
    }, ...prev]);
  };
  const loadScenario = (scenario) => {
    setScenarioName(scenario.name);
    setScenarioChain(scenario.chain.map(i => ({ ...i, id: uid(), status: 'pending', stdout: '', stderr: '' })));
  };

  if (!TECHNIQUES.length) return <EmptyDataView />;

  return (
    <div className="app">
      <Header
        route={route} meta={DATA_META}
        sessionLogCount={sessionLog.length}
        scenarioChainCount={scenarioChain.length}
        showSettings={showSettings} setShowSettings={setShowSettings}
      />
      {showSettings && (
        <SettingsStrip
          apiBase={apiBase} setApiBase={setApiBase}
          mockMode={mockMode} setMockMode={setMockMode}
          onClose={() => setShowSettings(false)}
        />
      )}
      <div className="app-body">
        {route.view === 'tactics' && (
          <TacticsView
            techniques={TECHNIQUES}
            tacticCounts={tacticCounts}
            hideTacticsWithoutCuration={hideTacticsWithoutCuration}
            setHideTacticsWithoutCuration={setHideTacticsWithoutCuration}
            search={search} setSearch={setSearch}
          />
        )}
        {route.view === 'techniques' && (
          <TechniquesView
            techniques={TECHNIQUES}
            tacticId={route.tacticId}
            tacticCounts={tacticCounts}
            sortMode={tacticListSort} setSortMode={setTacticListSort}
            curatedOnly={curatedOnly} setCuratedOnly={setCuratedOnly}
            connectivityFilter={connectivityFilter} setConnectivityFilter={setConnectivityFilter}
            platformFilter={platformFilter} setPlatformFilter={setPlatformFilter}
            search={search} setSearch={setSearch}
          />
        )}
        {route.view === 'detail' && (
          <DetailView
            technique={techniqueIndex[route.techniqueId]}
            techniqueId={route.techniqueId}
            detailTab={detailTab} setDetailTab={setDetailTab}
            huntPackTab={huntPackTab} setHuntPackTab={setHuntPackTab}
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
            scenarioName={scenarioName} setScenarioName={setScenarioName}
            chainRunning={chainRunning} runChain={runChain} resetChain={resetChain}
            removeFromChain={removeFromChain} moveChainItem={moveChainItem}
            setScenarioChain={setScenarioChain}
            saveScenario={saveScenario}
            savedScenarios={savedScenarios} loadScenario={loadScenario}
          />
        )}
        {route.view === 'session' && (
          <SessionLogView
            sessionLog={sessionLog} setSessionLog={setSessionLog}
            expandedLogId={expandedLogId} setExpandedLogId={setExpandedLogId}
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
  const isTactics = route.view === 'tactics';
  const isTechniques = route.view === 'techniques';
  const isDetail = route.view === 'detail';
  const isScenarios = route.view === 'scenarios';
  const isSession = route.view === 'session';

  const NavBtn = ({ path, label, count, active }) => (
    <button onClick={() => navigateTo(path)} className={`nav-btn ${active ? 'active' : ''}`}>
      {label}
      {count > 0 && <span className="nav-badge">{count}</span>}
    </button>
  );

  return (
    <div className="header">
      <button onClick={() => navigateTo('/')} className="header-brand">
        <div className="header-brand-name">BLUE TEAM TRAINER</div>
        <div className="header-brand-meta">
          {meta.merged_total || 0} TECHNIQUES · {meta.curated_count || 0} CURATED
        </div>
      </button>
      <div className="header-nav">
        <NavBtn path="/" label="Tactics" count={0} active={isTactics || isTechniques || isDetail} />
        <NavBtn path="/scenarios" label="Scenarios" count={scenarioChainCount} active={isScenarios} />
        <NavBtn path="/session" label="Session" count={sessionLogCount} active={isSession} />
      </div>
      <div className="header-right">
        <button onClick={() => setShowSettings(!showSettings)} className={`icon-btn ${showSettings ? 'active' : ''}`}>
          ⚙ SETTINGS
        </button>
      </div>
    </div>
  );
}

function SettingsStrip({ apiBase, setApiBase, mockMode, setMockMode, onClose }) {
  return (
    <div className="settings-strip">
      <div className="settings-field">
        <label className="settings-label">API base</label>
        <input className="settings-input" value={apiBase} onChange={e => setApiBase(e.target.value)} />
      </div>
      <div className="settings-field">
        <label className="settings-label">Mode</label>
        <button onClick={() => setMockMode(!mockMode)} className={`mode-pill ${mockMode ? 'mock' : 'live'}`}>
          {mockMode ? '⚠ MOCK MODE' : '● LIVE MODE'}
        </button>
      </div>
      <button onClick={onClose} className="icon-btn" style={{ marginLeft: 'auto' }}>✕ CLOSE</button>
    </div>
  );
}

// ===========================================================================
// View 1: Tactics grid
// ===========================================================================

function TacticsView({ techniques, tacticCounts, hideTacticsWithoutCuration, setHideTacticsWithoutCuration, search, setSearch }) {
  const searchResults = useMemo(() => {
    const q = search.toLowerCase().trim();
    if (!q) return null;
    return techniques.filter(t =>
      t.id.toLowerCase().includes(q) || t.name.toLowerCase().includes(q)
    ).slice(0, 25);
  }, [search, techniques]);

  const visibleTactics = TACTIC_ORDER.filter(tid => {
    if (hideTacticsWithoutCuration && tacticCounts[tid] && tacticCounts[tid].curated === 0) return false;
    return true;
  });

  return (
    <div className="view">
      <div className="landing-intro">
        <h1>Pick a tactic to begin</h1>
        <p>Each card represents one of the 14 MITRE ATT&amp;CK Enterprise tactics. Click through to see the techniques mapped to it.</p>
      </div>

      <div className="landing-controls">
        <input
          className="search-input"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Search by technique ID or name (e.g. T1566 or Spearphishing)"
        />
        <label className="checkbox-row">
          <input type="checkbox" checked={hideTacticsWithoutCuration} onChange={e => setHideTacticsWithoutCuration(e.target.checked)} />
          Hide tactics without curated content
        </label>
      </div>

      {searchResults && (
        <div className="search-results-panel">
          <div className="search-results-label">
            {searchResults.length} match{searchResults.length !== 1 ? 'es' : ''}
          </div>
          {searchResults.length === 0 ? (
            <div className="empty">No matches.</div>
          ) : (
            searchResults.map(t => (
              <button key={t.id} className="search-result-row" onClick={() => navigateTo(`/technique/${t.id}`)}>
                <span className={`tech-star ${t.curated ? '' : 'empty'}`}>{t.curated ? '★' : '·'}</span>
                <span className="tech-id">{t.id}</span>
                <span className="tech-name">{t.name}</span>
                <TacticBadge tacticId={t.tactic} />
              </button>
            ))
          )}
        </div>
      )}

      <div className="tactic-grid">
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
              className="tactic-card"
              style={tacticColorStyle(tid)}
            >
              <div className="tactic-card-id">{tid}</div>
              <div className="tactic-card-name">{meta.name}</div>
              <div className="tactic-card-counts">
                <span>{counts.total} technique{counts.total !== 1 ? 's' : ''}</span>
                {counts.curated > 0 && (
                  <span className="tactic-card-curated">★ {counts.curated}</span>
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
      if (connectivityFilter !== 'all') {
        const hasMatch = (t.atomicTests || []).some(at => {
          if (connectivityFilter === 'offline') return at.offlineCapable;
          if (connectivityFilter === 'staged') return !at.offlineCapable && at.prereqStage;
          if (connectivityFilter === 'online') return !at.offlineCapable && !at.prereqStage;
          return true;
        });
        if (!hasMatch) return false;
      }
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
      <div className="view">
        <div className="placeholder">Unknown tactic: {tacticId}.</div>
      </div>
    );
  }

  const counts = tacticCounts[tacticId] || { total: 0, curated: 0 };

  return (
    <div className="view">
      <div className="breadcrumb">
        <button className="breadcrumb-link" onClick={() => navigateTo('/')}>← Tactics</button>
        <span className="breadcrumb-sep">/</span>
        <span>{tacticId}</span>
      </div>

      <div className="page-head">
        <div className="page-head-id" style={{ color: `var(${meta.var})` }}>{tacticId}</div>
        <h2 className="page-head-title">{meta.name}</h2>
        <div className="page-head-meta">
          <span>{counts.total} technique{counts.total !== 1 ? 's' : ''}</span>
          {counts.curated > 0 && <span style={{ color: 'var(--accent)' }}>★ {counts.curated} curated</span>}
        </div>
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          value={search}
          onChange={e => setSearch(e.target.value)}
          placeholder="Filter…"
        />
        <PillGroup
          options={[['curated-first', '★ Curated first'], ['id', 'By ID']]}
          value={sortMode} setValue={setSortMode}
        />
        <label className="checkbox-row">
          <input type="checkbox" checked={curatedOnly} onChange={e => setCuratedOnly(e.target.checked)} />
          Curated only
        </label>
        <PillGroup
          label="Net"
          options={[
            ['all', 'All'],
            ['offline', '○ Offline'],
            ['staged', '◐ Staged'],
            ['online', '● Online'],
          ]}
          value={connectivityFilter} setValue={setConnectivityFilter}
        />
        <PillGroup
          label="Platform"
          options={[
            ['all', 'All'],
            ['windows', 'Windows'],
            ['linux', 'Linux'],
            ['macos', 'macOS'],
          ]}
          value={platformFilter} setValue={setPlatformFilter}
        />
      </div>

      <div className="result-count">
        Showing {filtered.length} technique{filtered.length !== 1 ? 's' : ''}
      </div>

      {filtered.length === 0 ? (
        <div className="empty">No techniques match the current filters.</div>
      ) : (
        <div className="tech-rows">
          {filtered.map(t => <TechniqueRow key={t.id} technique={t} />)}
        </div>
      )}
    </div>
  );
}

function PillGroup({ label, options, value, setValue }) {
  return (
    <div className="pill-group">
      {label && <span className="pill-group-label">{label}</span>}
      {options.map(([k, l]) => (
        <button
          key={k}
          onClick={() => setValue(k)}
          className={`pill ${value === k ? 'active' : ''}`}
        >{l}</button>
      ))}
    </div>
  );
}

function TechniqueRow({ technique }) {
  const testCount = (technique.atomicTests || []).length;
  const allOffline = testCount > 0 && (technique.atomicTests || []).every(t => t.offlineCapable);
  const anyStaged = (technique.atomicTests || []).some(t => !t.offlineCapable && t.prereqStage);
  const allOnline = testCount > 0 && (technique.atomicTests || []).every(t => !t.offlineCapable && !t.prereqStage);
  let aggregateBadge = null;
  if (allOffline) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: true, prereqStage: false }} />;
  else if (allOnline) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: false, prereqStage: false }} />;
  else if (anyStaged) aggregateBadge = <ConnectivityBadge test={{ offlineCapable: false, prereqStage: true }} />;

  const allPlatforms = new Set();
  (technique.atomicTests || []).forEach(t => (t.supportedPlatforms || []).forEach(p => allPlatforms.add(p)));

  return (
    <button onClick={() => navigateTo(`/technique/${technique.id}`)} className="tech-row">
      <span className={`tech-star ${technique.curated ? '' : 'empty'}`}>{technique.curated ? '★' : '·'}</span>
      <span className="tech-id">{technique.id}</span>
      <span className="tech-name">{technique.name}</span>
      <span className="tech-meta">{testCount} test{testCount !== 1 ? 's' : ''}</span>
      <PlatformBadge platforms={[...allPlatforms]} />
      {aggregateBadge}
      <span className="tech-arrow">›</span>
    </button>
  );
}

// ===========================================================================
// View 3: Detail
// ===========================================================================

function DetailView({
  technique, techniqueId, detailTab, setDetailTab,
  huntPackTab, setHuntPackTab, detonatingId,
  handleDetonate, handleCheckPrereqs, addToChain, scenarioChain,
}) {
  if (!technique) {
    return (
      <div className="view">
        <div className="placeholder">
          <div className="placeholder-title">Technique not found</div>
          <code>{techniqueId}</code> is not in the loaded library.
          <div style={{ marginTop: 12 }}>
            <button className="btn btn-secondary" onClick={() => navigateTo('/')}>← Back to tactics</button>
          </div>
        </div>
      </div>
    );
  }

  const tactics = technique.tactics && technique.tactics.length ? technique.tactics : [technique.tactic];
  const primaryTactic = tactics[0];
  const inChain = (testId) => scenarioChain.some(c => c.selectedTest && c.selectedTest.id === testId);

  return (
    <div className="view">
      <div className="breadcrumb">
        <button className="breadcrumb-link" onClick={() => navigateTo('/')}>Tactics</button>
        <span className="breadcrumb-sep">/</span>
        <button className="breadcrumb-link" onClick={() => navigateTo(`/tactic/${primaryTactic}`)}>
          {TACTIC_META[primaryTactic]?.name || primaryTactic}
        </button>
        <span className="breadcrumb-sep">/</span>
        <span>{technique.id}</span>
      </div>

      <div className="page-head">
        <div className="detail-head-row">
          {technique.curated && <span className="detail-head-star">★</span>}
          <span className="page-head-id text-faint">{technique.id}</span>
          {tactics.map(t => <TacticBadge key={t} tacticId={t} />)}
        </div>
        <h2 className="page-head-title">{technique.name}</h2>
        <div className="page-head-meta">
          <span>{(technique.atomicTests || []).length} atomic test{(technique.atomicTests || []).length !== 1 ? 's' : ''}</span>
          {!technique.curated && (
            <span style={{ color: 'var(--warn)' }}>
              No curated hunt pack yet — <a href="https://github.com/Incogn1toBro/BlueTeam-Trainer/blob/main/CONTRIBUTING.md" target="_blank" rel="noreferrer">contributions welcome</a>
            </span>
          )}
        </div>
      </div>

      <div className="detail-tabs">
        <button
          onClick={() => setDetailTab('tests')}
          className={`detail-tab ${detailTab === 'tests' ? 'active' : ''}`}
        >Atomic tests ({(technique.atomicTests || []).length})</button>
        <button
          onClick={() => setDetailTab('hunt')}
          disabled={!technique.curated}
          className={`detail-tab ${detailTab === 'hunt' ? 'active' : ''}`}
        >{technique.curated ? 'Hunt pack' : 'Hunt pack (not curated)'}</button>
      </div>

      {detailTab === 'tests' && (
        <div className="tests-list">
          {(technique.atomicTests || []).map(test => (
            <AtomicTestCard
              key={test.id} technique={technique} test={test}
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
        <div className="placeholder">
          <div className="placeholder-title">No curated hunt pack yet</div>
          This technique exists in the upstream Atomic Red Team library, but no analyst-facing hunt queries have been written for it yet. You can still detonate the atomic tests — open the “Atomic tests” tab — but you will need to write your own SPL / VQL / PowerShell queries to hunt the activity.
          <div style={{ marginTop: 12 }}>
            Contributions welcome — see <a href="https://github.com/Incogn1toBro/BlueTeam-Trainer/blob/main/CONTRIBUTING.md" target="_blank" rel="noreferrer">CONTRIBUTING.md</a> for how to add a hunt pack.
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
    <div className="test-card">
      <div className="test-card-meta">
        <span className="test-card-id">{test.id}</span>
        <ConnectivityBadge test={test} />
        <PlatformBadge platforms={test.supportedPlatforms} />
        {test.hasPrereqs && <span className="badge prereq">PREREQ</span>}
      </div>
      <div className="test-card-name">{test.name}</div>
      <div className="test-card-desc">{test.description}</div>
      <div className="test-card-actions">
        <button
          onClick={() => handleDetonate(technique, test)}
          disabled={isDetonating || !supportedOnWindows}
          title={!supportedOnWindows ? 'This test does not support Windows; the platform cannot detonate it.' : ''}
          className={`btn btn-detonate ${isDetonating ? 'detonating' : ''}`}
        >{isDetonating ? '⟳ DETONATING…' : '⚡ DETONATE'}</button>
        {test.hasPrereqs && (
          <button
            onClick={() => handleCheckPrereqs(technique, test)}
            disabled={isDetonating || !supportedOnWindows}
            className="btn btn-secondary"
          >⚙ CHECK PREREQS</button>
        )}
        <button
          onClick={() => addToChain(technique, test)}
          disabled={alreadyInChain || !supportedOnWindows}
          className={`btn btn-secondary ${alreadyInChain ? 'in-chain' : ''}`}
        >{alreadyInChain ? '✓ IN CHAIN' : '+ ADD TO CHAIN'}</button>
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
      <div className="pill-group" style={{ marginBottom: 14 }}>
        {tabs.map(([k, l, arr]) => (
          <button key={k} onClick={() => setHuntPackTab(k)} className={`pill ${huntPackTab === k ? 'active' : ''}`}>
            {l} {arr.length > 0 && <span className="text-faint" style={{ marginLeft: 4 }}>{arr.length}</span>}
          </button>
        ))}
      </div>
      {active[2].length === 0 ? (
        <div className="empty">No {active[1]} queries curated for this technique.</div>
      ) : (
        active[2].map((code, i) => <CodeBlock key={i} code={code} lang={active[0]} />)
      )}
    </div>
  );
}

// ===========================================================================
// View 4: Scenarios
// ===========================================================================

function ScenariosView({
  scenarioChain, scenarioName, setScenarioName,
  chainRunning, runChain, resetChain,
  removeFromChain, moveChainItem, setScenarioChain,
  saveScenario, savedScenarios, loadScenario,
}) {
  return (
    <div className="view">
      <div className="page-head">
        <h2 className="page-head-title">Scenarios</h2>
        <p className="page-head-meta">
          Chain multiple atomic tests together to simulate a full attack path.
          Open a technique, click <code>+ Add to chain</code>, then come back here to run the sequence.
        </p>
      </div>

      <div className="scenario-controls">
        <input
          className="filter-input"
          value={scenarioName}
          onChange={e => setScenarioName(e.target.value)}
          placeholder="Name this scenario"
          style={{ maxWidth: 360 }}
        />
        <span className="text-faint mono" style={{ fontSize: 11 }}>
          {scenarioChain.length} step{scenarioChain.length !== 1 ? 's' : ''}
        </span>
      </div>

      {scenarioChain.length === 0 ? (
        <div className="empty">Empty chain. Open a technique and click <strong>+ Add to chain</strong>.</div>
      ) : (
        <div>
          {scenarioChain.map((item, idx) => (
            <div key={item.id} className="chain-item">
              <div className="chain-rail">
                <StatusDot status={item.status} />
                {idx < scenarioChain.length - 1 && <div className="chain-rail-line" />}
              </div>
              <div className={`chain-card ${item.status || ''}`}>
                <div className="chain-card-head">
                  <div className="chain-card-meta">
                    <span className="chain-card-step">#{idx + 1}</span>
                    <button onClick={() => navigateTo(`/technique/${item.technique.id}`)} className="breadcrumb-link" style={{ fontSize: 13, fontWeight: 500, color: 'var(--text)' }}>
                      {item.technique.id} — {item.technique.name}
                    </button>
                  </div>
                  <div className="chain-card-actions">
                    <button onClick={() => moveChainItem(item.id, -1)} disabled={idx === 0} className="chain-action-btn">↑</button>
                    <button onClick={() => moveChainItem(item.id, 1)} disabled={idx === scenarioChain.length - 1} className="chain-action-btn">↓</button>
                    <button onClick={() => removeFromChain(item.id)} className="chain-action-btn danger">✕</button>
                  </div>
                </div>
                <div className="text-muted mono" style={{ fontSize: 11 }}>{item.selectedTest.name}</div>
                {item.stderr && (
                  <pre className="log-stream stderr" style={{ marginTop: 8 }}>{item.stderr}</pre>
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {scenarioChain.length > 0 && (
        <div className="chain-controls">
          <button onClick={runChain} disabled={chainRunning} className="btn btn-detonate" style={{ flex: 1 }}>
            {chainRunning ? '⟳ RUNNING CHAIN…' : '⚡ RUN CHAIN'}
          </button>
          <button onClick={resetChain} disabled={chainRunning} className="btn btn-secondary">RESET</button>
          <button onClick={saveScenario} disabled={chainRunning} className="btn btn-secondary" style={{ color: 'var(--accent)', borderColor: 'var(--accent)' }}>SAVE</button>
          <button onClick={() => setScenarioChain([])} disabled={chainRunning} className="btn btn-secondary" style={{ color: 'var(--err)' }}>CLEAR</button>
        </div>
      )}

      {savedScenarios.length > 0 && (
        <div style={{ marginTop: 32 }}>
          <div className="search-results-label" style={{ marginBottom: 10 }}>Saved scenarios</div>
          <div className="tech-rows">
            {savedScenarios.map(s => (
              <button key={s.id} onClick={() => loadScenario(s)} className="tech-row">
                <span className="tech-star">·</span>
                <span className="tech-name">{s.name}</span>
                <span className="tech-meta">{s.chain.length} step{s.chain.length !== 1 ? 's' : ''}</span>
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
    <div className="view">
      <div className="page-head" style={{ display: 'flex', alignItems: 'flex-end', justifyContent: 'space-between' }}>
        <div>
          <h2 className="page-head-title">Session log</h2>
          <p className="page-head-meta">{sessionLog.length} entr{sessionLog.length === 1 ? 'y' : 'ies'} this session</p>
        </div>
        {sessionLog.length > 0 && (
          <button onClick={() => setSessionLog([])} className="btn btn-secondary" style={{ color: 'var(--err)' }}>CLEAR LOG</button>
        )}
      </div>

      {sessionLog.length === 0 ? (
        <div className="empty">Nothing detonated yet.</div>
      ) : (
        <div className="tech-rows">
          {sessionLog.map(entry => {
            const expanded = expandedLogId === entry.id;
            const hasOutput = (entry.stdout && entry.stdout.trim()) || (entry.stderr && entry.stderr.trim());
            return (
              <div key={entry.id} className={`log-entry ${entry.status}`}>
                <button
                  onClick={() => hasOutput && setExpandedLogId(expanded ? null : entry.id)}
                  className="log-entry-head"
                  style={{ cursor: hasOutput ? 'pointer' : 'default' }}
                >
                  <span className="log-time">{entry.timestamp.toLocaleTimeString()}</span>
                  <span className="log-tid">{entry.technique.id}</span>
                  <span className="log-name">
                    <span className="log-name-tech">{entry.technique.name}</span>
                    <span className="log-name-test">· {entry.atomicTest.name}</span>
                  </span>
                  {entry.kind === 'prereq' && <span className="badge prereq">PREREQ</span>}
                  <span className="log-duration">{entry.duration}ms</span>
                  <span className={`log-status ${entry.status}`}>
                    {entry.status === 'success' ? '✓ SUCCESS' : '✕ FAILED'}
                  </span>
                  {hasOutput && <span className="log-expand">{expanded ? '▾' : '▸'}</span>}
                </button>
                {expanded && hasOutput && (
                  <div className="log-output">
                    {entry.stdout && entry.stdout.trim() && (
                      <>
                        <div className="log-stream-label stdout">STDOUT</div>
                        <pre className="log-stream">{entry.stdout}</pre>
                      </>
                    )}
                    {entry.stderr && entry.stderr.trim() && (
                      <>
                        <div className="log-stream-label stderr">STDERR</div>
                        <pre className="log-stream stderr">{entry.stderr}</pre>
                      </>
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
// Empty data view
// ===========================================================================

function EmptyDataView() {
  return (
    <div className="empty-data">
      <div className="empty-data-card">
        <div className="empty-data-label">NO TECHNIQUE LIBRARY EMBEDDED</div>
        <div className="empty-data-body">
          The HTML was built without <code>data/techniques.json</code>. Run the build pipeline:
        </div>
        <pre className="empty-data-cmd">{`./build.sh`}</pre>
        <div className="empty-data-foot">
          This pulls Atomic Red Team upstream, merges your curation overlay, and rebuilds the HTML with the technique library embedded.
        </div>
      </div>
    </div>
  );
}
