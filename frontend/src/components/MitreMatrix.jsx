// Exactly the MITRE techniques the gateway actually emits (auth.py, detect.py,
// main.py) - deliberately not a generic ATT&CK reference list. Keep this in sync
// with the backend's mitre tags; showing a technique here the gateway can't
// actually detect would be a real, dashboard-level false claim.
const TECHNIQUES = [
  { id: 'T1078', name: 'Valid Accounts', hint: 'bad tokens, BOLA, missing auth' },
  { id: 'T1119', name: 'Automated Collection', hint: 'enumeration, scraping' },
  { id: 'T1548', name: 'Abuse Elevation Control', hint: 'BFLA' },
  { id: 'T1499', name: 'Endpoint Denial of Service', hint: 'rate abuse' },
  { id: 'T1550', name: 'Use Alternate Auth', hint: 'audience/issuer mismatch' },
  { id: 'T1087', name: 'Account Discovery', hint: 'behavioral anomaly (control plane)' }
];

function severity(count) {
  if (count === 0) return { rule: 'border-l-canvas-line-strong', text: 'text-ink-faint' };
  if (count < 5) return { rule: 'border-l-risk-caution', text: 'text-risk-caution' };
  return { rule: 'border-l-risk-danger', text: 'text-risk-danger' };
}

export default function MitreMatrix({ counts = {} }) {
  return (
    <div className="glass-panel rounded-lg p-4">
      <h3 className="mb-3 font-display text-sm font-semibold text-ink">MITRE ATT&amp;CK matrix</h3>
      <div className="grid grid-cols-2 gap-2 sm:grid-cols-3 xl:grid-cols-4">
        {TECHNIQUES.map((t) => {
          const count = counts[t.id] || 0;
          const s = severity(count);
          return (
            <div key={t.id} className={`border-l-[3px] ${s.rule} bg-canvas-raised p-3`}>
              <div className="flex items-baseline justify-between">
                <span className="font-mono text-[11px] text-ink-muted">{t.id}</span>
                <span className={`font-mono text-lg font-semibold tabular-nums ${s.text}`}>{count}</span>
              </div>
              <div className="mt-1 text-xs font-medium text-ink">{t.name}</div>
              <div className="text-[10px] text-ink-faint">{t.hint}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
