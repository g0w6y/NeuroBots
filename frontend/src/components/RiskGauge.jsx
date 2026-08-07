function riskColor(score) {
  if (score <= 30) return { stroke: '#5fa86f', text: 'text-risk-safe', label: 'Safe' };
  if (score <= 60) return { stroke: '#c98a3c', text: 'text-risk-caution', label: 'Caution' };
  return { stroke: '#c85c4a', text: 'text-risk-danger', label: 'Danger' };
}

// tick-mark ring, every 10%; the 30/60 marks pick up the same colors as the
// safe/caution/danger bands they introduce, so the ring doubles as a legend
const TICKS = Array.from({ length: 10 }, (_, i) => i * 10);
const THRESHOLD_COLOR = { 30: '#c98a3c', 60: '#c85c4a' };

function polar(cx, cy, r, angleDeg) {
  const rad = (angleDeg * Math.PI) / 180;
  return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) };
}

export default function RiskGauge({ score = 0 }) {
  const { stroke, text, label } = riskColor(score);
  const radius = 80;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (Math.min(score, 100) / 100) * circumference;

  return (
    <div className="relative flex h-52 w-52 shrink-0 items-center justify-center">
      <svg width="200" height="200" viewBox="0 0 200 200" className="-rotate-90">
        {TICKS.map((t) => {
          const angle = (t / 100) * 360;
          const thresholdColor = THRESHOLD_COLOR[t];
          const inner = polar(100, 100, thresholdColor ? 87 : 88, angle);
          const outer = polar(100, 100, thresholdColor ? 99 : 93, angle);
          return (
            <line
              key={t}
              x1={inner.x}
              y1={inner.y}
              x2={outer.x}
              y2={outer.y}
              stroke={thresholdColor || '#3a362f'}
              strokeWidth={thresholdColor ? 2.5 : 1.5}
              strokeLinecap="round"
            />
          );
        })}
        <circle cx="100" cy="100" r={radius} fill="none" stroke="#211f1c" strokeWidth="14" />
        <circle
          cx="100"
          cy="100"
          r={radius}
          fill="none"
          stroke={stroke}
          strokeWidth="14"
          strokeLinecap="round"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          style={{ transition: 'stroke-dashoffset 0.6s ease, stroke 0.6s ease' }}
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className="font-mono text-5xl font-semibold tabular-nums text-ink">
          {String(Math.round(score)).padStart(3, '0')}
        </span>
        <span className={`mt-1 font-display text-xs font-semibold uppercase tracking-wide ${text}`}>{label}</span>
      </div>
    </div>
  );
}
