import { useState, useEffect } from 'react';
import PropTypes from 'prop-types';
import { api } from '../api.js';

const TACTIC_COLOR = {
  'Reconnaissance':       '#808590',
  'Initial Access':       '#cc2233',
  'Execution':            '#e8574a',
  'Persistence':          '#f09a3a',
  'Privilege Escalation': '#e8cc42',
  'Defense Evasion':      '#6fc8f0',
  'Credential Access':    '#c07af0',
  'Discovery':            '#5b8af5',
  'Lateral Movement':     '#39d353',
  'Collection':           '#3bc9c9',
  'Command and Control':  '#f07080',
  'Exfiltration':         '#a8d8a8',
  'Impact':               '#cc2233',
};

function buildByTactic(techniques) {
  const byTactic = {};
  for (const t of techniques) {
    if (!byTactic[t.tactic]) {
      byTactic[t.tactic] = [];
    }
    byTactic[t.tactic].push(t);
  }
  return byTactic;
}

function getFilterFn(filter) {
  if (filter === 'covered') {
    return t => t.used;
  }
  if (filter === 'uncovered') {
    return t => !t.used;
  }
  return () => true;
}

function calcPct(stats) {
  return stats.total_techniques ? Math.round((stats.covered / stats.total_techniques) * 100) : 0;
}

function MitreCoverageBar({ pct, accent }) {
  return (
    <div style={{ minWidth: 160 }}>
      <div style={{ height: 5, background: '#1e2029', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${pct}%`, background: accent, borderRadius: 3, transition: 'width .3s' }} />
      </div>
      <div style={{ fontSize: 9, color: '#505560', marginTop: 3, fontFamily: 'JetBrains Mono' }}>{pct}% coverage</div>
    </div>
  );
}

function MitreFilterButtons({ filter, setFilter, accent }) {
  return (
    <div style={{ display: 'flex', gap: 5 }}>
      {['all', 'covered', 'uncovered'].map(f => (
        <button key={f} onClick={() => setFilter(f)} style={{
          background: filter === f ? accent + '22' : 'transparent',
          border: `1px solid ${filter === f ? accent + '66' : '#2a2d35'}`,
          borderRadius: 4, padding: '3px 9px', cursor: 'pointer',
          color: filter === f ? accent : '#505560',
          fontSize: 9, fontFamily: 'JetBrains Mono', textTransform: 'uppercase',
        }}>{f}</button>
      ))}
    </div>
  );
}

function MitreTacticColumn({ tactic, techs, accent, onNavigate }) {
  const color = TACTIC_COLOR[tactic] || '#606570';
  const usedCount = techs.filter(t => t.used).length;
  return (
    <div style={{ width: 155, flexShrink: 0 }}>
      <div style={{ padding: '6px 8px', marginBottom: 8, borderBottom: `2px solid ${color}66` }}>
        <div style={{ fontSize: 9, fontWeight: 700, color, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
          {tactic}
        </div>
        <div style={{ fontSize: 8, color: '#404550', marginTop: 1, fontFamily: 'JetBrains Mono' }}>
          {usedCount}/{techs.length}
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
        {techs.map(t => (
          <TechCell key={t.id} tech={t} accent={accent} onOpenKB={() => onNavigate?.('kb')} />
        ))}
      </div>
    </div>
  );
}

function MitreUnmappedSection({ unmapped }) {
  return (
    <div style={{ marginTop: 24, paddingTop: 16, borderTop: '1px solid #1e2029' }}>
      <div style={{ fontSize: 10, color: '#505560', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '0.1em' }}>
        Unmapped (in steps but not in library)
      </div>
      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
        {unmapped.map((u) => (
          <span key={u.id || u.name || u.label} style={{
            background: '#ffffff08', border: '1px solid #2a2d35', borderRadius: 4,
            padding: '3px 8px', fontSize: 9, fontFamily: 'JetBrains Mono', color: '#606570',
          }}>
            {u.id}{u.name ? ` · ${u.name}` : ''}{u.label ? ` (${u.label})` : ''}
          </span>
        ))}
      </div>
    </div>
  );
}

function MitreMatrix({ tactics, byTactic, filterFn, accent, onNavigate, unmapped }) {
  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '16px 24px' }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'flex-start', minWidth: 'max-content' }}>
        {tactics.map(tactic => {
          const techs = (byTactic[tactic] || []).filter(filterFn);
          if (techs.length === 0) {
            return null;
          }
          return <MitreTacticColumn key={tactic} tactic={tactic} techs={techs} accent={accent} onNavigate={onNavigate} />;
        })}
      </div>
      {unmapped?.length > 0 && <MitreUnmappedSection unmapped={unmapped} />}
    </div>
  );
}

function MitreNotSeeded() {
  return (
    <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ textAlign: 'center', maxWidth: 400 }}>
        <div style={{ fontSize: 28, marginBottom: 12, opacity: 0.3 }}>⬡</div>
        <div style={{ fontSize: 13, color: '#505560', marginBottom: 8 }}>MITRE ATT&CK library not in KB</div>
        <div style={{ fontSize: 11, color: '#404550', lineHeight: 1.6, marginBottom: 16 }}>
          Click <strong style={{ color: '#c8cdd6' }}>Seed to KB</strong> to create 62 global KB articles
          (one per technique). After seeding, articles become editable and searchable,
          and this matrix shows coverage based on your Attack Path steps.
        </div>
      </div>
    </div>
  );
}

function TechCell({ tech, accent, onOpenKB }) {
  const [hover, setHover] = useState(false);
  const color = TACTIC_COLOR[tech.tactic] || '#606570';
  const used = tech.used;

  return (
    <button
      type="button"
      onMouseEnter={() => setHover(true)}
      onMouseLeave={() => setHover(false)}
      onClick={() => tech.kb_id && onOpenKB(tech.kb_id)}
      onKeyDown={e => {
        if ((e.key === 'Enter' || e.key === ' ') && tech.kb_id) {
          e.preventDefault();
          onOpenKB(tech.kb_id);
        }
      }}
      style={{
        position: 'relative',
        padding: '5px 8px',
        borderRadius: 5,
        border: used ? `1px solid ${color}88` : '1px solid #1e2029',
        background: (() => { if (used) { return `${color}18`; } if (hover) { return '#ffffff05'; } return 'transparent'; })(),
        cursor: tech.kb_id ? 'pointer' : 'default',
        transition: 'background .1s',
        minWidth: 130,
        textAlign: 'left',
      }}
    >
      <div style={{
        fontSize: 9,
        fontFamily: 'JetBrains Mono',
        color: used ? color : '#404550',
        marginBottom: 2,
        fontWeight: used ? 700 : 400,
      }}>
        {tech.id}
      </div>
      <div style={{
        fontSize: 10,
        color: used ? '#c8cdd6' : '#505560',
        lineHeight: 1.3,
      }}>
        {tech.name}
      </div>
      {used && (
        <div style={{
          position: 'absolute', top: 4, right: 6,
          width: 6, height: 6, borderRadius: '50%',
          background: color, boxShadow: `0 0 6px ${color}`,
        }} />
      )}
      {hover && tech.kb_id && (
        <div style={{
          position: 'absolute', bottom: 4, right: 6,
          fontSize: 7, color: '#404550', fontFamily: 'JetBrains Mono',
        }}>KB→</div>
      )}
    </button>
  );
}

const techPropType = PropTypes.shape({
  id: PropTypes.string,
  name: PropTypes.string,
  tactic: PropTypes.string,
  used: PropTypes.bool,
  kb_id: PropTypes.any,
});

const unmappedPropType = PropTypes.shape({
  id: PropTypes.string,
  name: PropTypes.string,
  label: PropTypes.string,
});

MitreCoverageBar.propTypes = {
  pct: PropTypes.number.isRequired,
  accent: PropTypes.string.isRequired,
};

MitreFilterButtons.propTypes = {
  filter: PropTypes.string.isRequired,
  setFilter: PropTypes.func.isRequired,
  accent: PropTypes.string.isRequired,
};

MitreTacticColumn.propTypes = {
  tactic: PropTypes.string.isRequired,
  techs: PropTypes.arrayOf(techPropType).isRequired,
  accent: PropTypes.string.isRequired,
  onNavigate: PropTypes.func,
};

MitreUnmappedSection.propTypes = {
  unmapped: PropTypes.arrayOf(unmappedPropType).isRequired,
};

MitreMatrix.propTypes = {
  tactics: PropTypes.arrayOf(PropTypes.string).isRequired,
  byTactic: PropTypes.object.isRequired,
  filterFn: PropTypes.func.isRequired,
  accent: PropTypes.string.isRequired,
  onNavigate: PropTypes.func,
  unmapped: PropTypes.arrayOf(unmappedPropType),
};

TechCell.propTypes = {
  tech: techPropType.isRequired,
  accent: PropTypes.string.isRequired,
  onOpenKB: PropTypes.func.isRequired,
};

export default function MitreView({ selectedProject, accent, onNavigate }) {
  const [data, setData] = useState(null);
  const [loading, setLoading] = useState(false);
  const [seeding, setSeeding] = useState(false);
  const [filter, setFilter] = useState('all');

  const load = () => {
    if (!selectedProject) {
      return;
    }
    setLoading(true);
    api.getMitreCoverage(selectedProject)
      .then(setData)
      .catch(() => setData(null))
      .finally(() => setLoading(false));
  };

  useEffect(load, [selectedProject]);

  const seedToKB = async () => {
    setSeeding(true);
    try {
      const r = await api.seedMitreKB();
      alert(`Seeded ${r.created} new techniques to KB (${r.skipped} already existed)`);
      load();
    } catch (e) {
      alert('Seed failed: ' + e.message);
    } finally {
      setSeeding(false);
    }
  };

  if (!selectedProject) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#404550' }}>
        Select a project
      </div>
    );
  }

  if (loading) {
    return (
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', height: '100%', color: '#505560', fontSize: 12 }}>
        Loading…
      </div>
    );
  }

  const tactics = data?.tactic_order || [];
  const techniques = data?.techniques || [];
  const stats = data?.stats || {};
  const kbSeeded = data?.kb_seeded ?? false;
  const byTactic = buildByTactic(techniques);
  const filterFn = getFilterFn(filter);
  const pct = calcPct(stats);

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden' }}>
      <div style={{ padding: '14px 24px', borderBottom: '1px solid #1e2029', display: 'flex', alignItems: 'center', gap: 14, flexShrink: 0, flexWrap: 'wrap' }}>
        <div style={{ flex: 1, minWidth: 200 }}>
          <div style={{ fontSize: 13, fontWeight: 700, color: '#f0f2f6', fontFamily: 'Space Grotesk' }}>MITRE ATT&amp;CK Coverage</div>
          <div style={{ fontSize: 10, color: '#505560', marginTop: 2 }}>
            {kbSeeded
              ? `${stats.covered} / ${stats.total_techniques} techniques mapped · sourced from KB`
              : 'Techniques not seeded to KB yet'}
            {stats.steps_total > 0 && ` · ${stats.steps_with_mitre} / ${stats.steps_total} attack path steps have MITRE IDs`}
          </div>
        </div>
        {kbSeeded && <MitreCoverageBar pct={pct} accent={accent} />}
        {kbSeeded && <MitreFilterButtons filter={filter} setFilter={setFilter} accent={accent} />}
        <button
          onClick={seedToKB}
          disabled={seeding}
          style={{
            background: kbSeeded ? 'transparent' : accent + '22',
            border: `1px solid ${kbSeeded ? '#2a2d35' : accent + '66'}`,
            borderRadius: 5, padding: '5px 12px', cursor: 'pointer',
            color: kbSeeded ? '#505560' : accent,
            fontSize: 10, fontFamily: 'JetBrains Mono',
            opacity: seeding ? 0.5 : 1,
          }}
        >
          {seeding ? 'Seeding…' : (() => { if (kbSeeded) { return 'Re-seed KB'; } return 'Seed to KB'; })()}
        </button>
        {kbSeeded && onNavigate && (
          <button
            onClick={() => onNavigate('kb')}
            style={{
              background: 'transparent', border: '1px solid #2a2d35',
              borderRadius: 5, padding: '5px 12px', cursor: 'pointer',
              color: '#505560', fontSize: 10, fontFamily: 'JetBrains Mono',
            }}
          >
            Open KB →
          </button>
        )}
      </div>
      {!kbSeeded && <MitreNotSeeded />}
      {kbSeeded && (
        <MitreMatrix
          tactics={tactics}
          byTactic={byTactic}
          filterFn={filterFn}
          accent={accent}
          onNavigate={onNavigate}
          unmapped={data?.unmapped}
        />
      )}
    </div>
  );
}

MitreView.propTypes = {
  selectedProject: PropTypes.any,
  accent: PropTypes.string.isRequired,
  onNavigate: PropTypes.func,
};
