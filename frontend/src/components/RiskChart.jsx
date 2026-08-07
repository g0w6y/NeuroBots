import { memo } from 'react';
import { LineChart, Line, XAxis, YAxis, Tooltip, ResponsiveContainer, PieChart, Pie, Cell, CartesianGrid } from 'recharts';

const PIE_COLORS = { allowed: '#5fa86f', challenged: '#c98a3c', blocked: '#c85c4a' };

const tooltipStyle = {
  background: '#1a1917',
  border: '1px solid #2c2925',
  borderRadius: 4,
  fontFamily: "'IBM Plex Mono', monospace",
  fontSize: 12,
  color: '#ede9e4'
};

function RiskChart({ metrics }) {
  const timeseries = metrics?.timeseries ?? [];
  const pieData = [
    { name: 'allowed', value: metrics?.allowed ?? 0 },
    { name: 'challenged', value: metrics?.challenged ?? 0 },
    { name: 'blocked', value: metrics?.blocked ?? 0 }
  ];
  const total = pieData.reduce((s, d) => s + d.value, 0);

  return (
    <div className="grid grid-cols-1 gap-4 lg:grid-cols-[1.6fr_1fr]">
      <div className="glass-panel rounded-lg p-4">
        <h3 className="mb-3 font-display text-sm font-semibold text-ink">Decisions over time — last 2 minutes</h3>
        <ResponsiveContainer width="100%" height={180}>
          <LineChart data={timeseries}>
            <CartesianGrid stroke="#211f1c" vertical={false} />
            <XAxis dataKey="time" stroke="#6b655c" fontSize={10} tickLine={false} axisLine={false} interval={3} />
            <YAxis stroke="#6b655c" fontSize={10} tickLine={false} axisLine={false} width={24} allowDecimals={false} />
            <Tooltip contentStyle={tooltipStyle} />
            <Line type="monotone" dataKey="allowed" stroke="#5fa86f" strokeWidth={2} dot={false} isAnimationActive={false} />
            <Line type="monotone" dataKey="challenged" stroke="#c98a3c" strokeWidth={2} dot={false} isAnimationActive={false} />
            <Line type="monotone" dataKey="blocked" stroke="#c85c4a" strokeWidth={2} dot={false} isAnimationActive={false} />
          </LineChart>
        </ResponsiveContainer>
      </div>

      <div className="glass-panel rounded-lg p-4">
        <h3 className="mb-3 font-display text-sm font-semibold text-ink">Decision split</h3>
        <div className="flex items-center gap-4">
          <ResponsiveContainer width={120} height={120}>
            <PieChart>
              <Pie data={pieData} dataKey="value" innerRadius={35} outerRadius={55} paddingAngle={3}>
                {pieData.map((entry) => (
                  <Cell key={entry.name} fill={PIE_COLORS[entry.name]} stroke="none" />
                ))}
              </Pie>
              <Tooltip contentStyle={tooltipStyle} />
            </PieChart>
          </ResponsiveContainer>
          <div className="flex flex-col gap-1.5 font-mono text-xs">
            {pieData.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full" style={{ background: PIE_COLORS[d.name] }} />
                <span className="capitalize text-ink-muted">{d.name}</span>
                <span className="text-ink">{total ? Math.round((d.value / total) * 100) : 0}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

export default memo(RiskChart);
