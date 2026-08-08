// Shared panel chrome. Pulled out of Dashboard.jsx so any panel - not just
// the ones living directly in Dashboard's JSX - can use the same bordered
// title-bar treatment instead of hand-rolling a near-identical header (which
// is how Security Posture, MitreMatrix and ThreatFeed each ended up with
// three slightly different implementations of the same thing).

export function Icon({ name, className = '' }) {
  return (
    <span className={`material-symbols-outlined ${className}`} aria-hidden="true">
      {name}
    </span>
  );
}

export function PanelHeader({ icon, children, tone = 'default', right }) {
  const toneText = { default: 'text-ink-muted', accent: 'text-accent', danger: 'text-risk-danger' }[tone];
  return (
    <div className="flex items-center justify-between border-b border-white/5 bg-white/[0.02] px-4 py-2.5">
      <span className={`label-caps flex items-center gap-2 ${toneText}`}>
        {icon ? <Icon name={icon} className="text-[16px]" /> : null}
        {children}
      </span>
      {right}
    </div>
  );
}
