import { PanelHeader } from './PanelHeader.jsx';

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
    <div className="glass-panel overflow-hidden rounded-lg">
      <PanelHeader icon="grid_view" tone="accent">MITRE ATT&amp;CK matrix</PanelHeader>

      {/* Fixed at 2 columns rather than viewport breakpoints (sm:/xl:) - this
          panel always lives in a narrow ~3/12 grid column next to Threat Feed,
          not the full viewport, so a breakpoint like xl:grid-cols-4 fires from
          screen width while the column itself stays a few hundred px wide,
          cramming 4 tiles into no room. 2 columns also divides the 6
          techniques evenly into 3 full rows - no ragged half-empty last row
          at any width. */}
      <div className="grid grid-cols-2 gap-2 p-4">
        {TECHNIQUES.map((t) => {
          const count = counts[t.id] || 0;
          const s = severity(count);
          return (
            <div key={t.id} className={`border-l-[3px] ${s.rule} bg-canvas-raised p-3`}>
              <div className="flex items-baseline justify-between gap-2">
                <span className="font-mono text-[11px] text-ink-muted">{t.id}</span>
                <span className={`font-mono text-lg font-semibold tabular-nums ${s.text}`}>{count}</span>
              </div>
              <div className="mt-1 text-xs font-medium leading-snug text-ink">{t.name}</div>
              <div className="mt-0.5 text-[10px] leading-snug text-ink-faint">{t.hint}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}
