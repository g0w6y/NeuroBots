import { useEffect, useRef, useState, useMemo } from 'react';
import * as d3 from 'd3';

export default function NetworkGraph({ data, onSelectNode }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredItem, setHoveredItem] = useState(null);
  const [filterAnomalousOnly, setFilterAnomalousOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [zoomLevel, setZoomLevel] = useState(1);

  const rawNodes = data?.nodes || [];
  const rawEdges = data?.edges || [];

  // Filter nodes & edges if "Anomalous Only" is checked
  const { nodes, links } = useMemo(() => {
    let filteredEdges = rawEdges;
    if (filterAnomalousOnly) {
      filteredEdges = rawEdges.filter((e) => e.is_anomalous || e.is_cross_tenant);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase().trim();
      filteredEdges = filteredEdges.filter(
        (e) =>
          e.source.toLowerCase().includes(q) ||
          e.target.toLowerCase().includes(q) ||
          (e.label && e.label.toLowerCase().includes(q))
      );
    }

    const nodeIdsInEdges = new Set();
    filteredEdges.forEach((e) => {
      nodeIdsInEdges.add(typeof e.source === 'object' ? e.source.id : e.source);
      nodeIdsInEdges.add(typeof e.target === 'object' ? e.target.id : e.target);
    });

    const activeNodes = filterAnomalousOnly
      ? rawNodes.filter((n) => nodeIdsInEdges.has(n.id) || n.status === 'blocked' || n.status === 'flagged')
      : rawNodes;

    // Deep copy for D3 force simulation to mutate safely
    const formattedNodes = activeNodes.map((n) => ({ ...n }));
    const activeNodeIdSet = new Set(formattedNodes.map((n) => n.id));

    const formattedLinks = filteredEdges
      .filter((e) => {
        const s = typeof e.source === 'object' ? e.source.id : e.source;
        const t = typeof e.target === 'object' ? e.target.id : e.target;
        return activeNodeIdSet.has(s) && activeNodeIdSet.has(t);
      })
      .map((e) => ({
        ...e,
        source: typeof e.source === 'object' ? e.source.id : e.source,
        target: typeof e.target === 'object' ? e.target.id : e.target
      }));

    return { nodes: formattedNodes, links: formattedLinks };
  }, [rawNodes, rawEdges, filterAnomalousOnly, searchQuery]);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 800;
    const height = 560;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove(); // Clear previous render

    // Define SVG Filters & Markers for Flashing Red Anomalies & Arrows
    const defs = svg.append('defs');

    // Glow filter for anomalous edges & blocked nodes
    const glowFilter = defs.append('filter').attr('id', 'glow-red').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Cyan glow for normal active nodes
    const cyanFilter = defs.append('filter').attr('id', 'glow-cyan').attr('x', '-50%').attr('y', '-50%').attr('width', '200%').attr('height', '200%');
    cyanFilter.append('feGaussianBlur').attr('stdDeviation', '3').attr('result', 'coloredBlur');
    const feMergeCyan = cyanFilter.append('feMerge');
    feMergeCyan.append('feMergeNode').attr('in', 'coloredBlur');
    feMergeCyan.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow markers
    defs
      .append('marker')
      .attr('id', 'arrow-normal')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 6)
      .attr('markerHeight', 6)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#38bdf8');

    defs
      .append('marker')
      .attr('id', 'arrow-anomaly')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 22)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#ff0055');

    // Root Group for Zoom
    const g = svg.append('g').attr('class', 'graph-group');

    // Zoom behavior
    const zoom = d3
      .zoom()
      .scaleExtent([0.3, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setZoomLevel(event.transform.k);
      });

    svg.call(zoom);

    // Initial positioning by layer: Users (Left) -> Endpoints (Middle) -> Resources (Right)
    nodes.forEach((node) => {
      if (node.type === 'user') {
        node.x = width * 0.15 + (Math.random() - 0.5) * 50;
        node.y = height * 0.5 + (Math.random() - 0.5) * 300;
      } else if (node.type === 'endpoint') {
        node.x = width * 0.5 + (Math.random() - 0.5) * 50;
        node.y = height * 0.5 + (Math.random() - 0.5) * 200;
      } else {
        node.x = width * 0.85 + (Math.random() - 0.5) * 50;
        node.y = height * 0.5 + (Math.random() - 0.5) * 300;
      }
    });

    // Force Simulation Setup
    const simulation = d3
      .forceSimulation(nodes)
      .force(
        'link',
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance((d) => (d.is_anomalous ? 160 : 130))
      )
      .force('charge', d3.forceManyBody().strength(-350))
      .force('collision', d3.forceCollide().radius(38))
      .force('y', d3.forceY(height / 2).strength(0.15));

    // Render Links
    const linkGroup = g.append('g').attr('class', 'links');
    const link = linkGroup
      .selectAll('g')
      .data(links)
      .enter()
      .append('g')
      .attr('class', 'link-item');

    // Base edge lines
    const linkLine = link
      .append('line')
      .attr('stroke', (d) => (d.is_cross_tenant || d.is_anomalous ? '#ff0055' : '#1e293b'))
      .attr('stroke-width', (d) => (d.is_cross_tenant || d.is_anomalous ? 3 : 1.5))
      .attr('stroke-dasharray', (d) => (d.is_cross_tenant || d.is_anomalous ? '6 4' : 'none'))
      .attr('marker-end', (d) => (d.is_cross_tenant || d.is_anomalous ? 'url(#arrow-anomaly)' : 'url(#arrow-normal)'))
      .attr('filter', (d) => (d.is_cross_tenant || d.is_anomalous ? 'url(#glow-red)' : undefined));

    // Animated pulse overlay line for anomalous cross-tenant edges
    link
      .filter((d) => d.is_cross_tenant || d.is_anomalous)
      .append('line')
      .attr('class', 'animate-pulse')
      .attr('stroke', '#ff2a6d')
      .attr('stroke-width', 4)
      .attr('stroke-linecap', 'round')
      .attr('opacity', 0.8)
      .attr('filter', 'url(#glow-red)');

    // Edge Labels
    const linkText = link
      .append('text')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .attr('fill', (d) => (d.is_cross_tenant || d.is_anomalous ? '#ff0055' : '#64748b'))
      .attr('text-anchor', 'middle')
      .attr('dy', -4)
      .text((d) => (d.is_cross_tenant ? '⚡ CROSS-TENANT BOLA' : d.label || ''));

    // Render Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const node = nodeGroup
      .selectAll('g')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', 'node-item cursor-pointer')
      .call(
        d3
          .drag()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.3).restart();
            d.fx = d.x;
            d.fy = d.y;
          })
          .on('drag', (event, d) => {
            d.fx = event.x;
            d.fy = event.y;
          })
          .on('end', (event, d) => {
            if (!event.active) simulation.alphaTarget(0);
            d.fx = null;
            d.fy = null;
          })
      )
      .on('click', (event, d) => {
        setSelectedNode(d);
        if (onSelectNode) onSelectNode(d);
      })
      .on('mouseenter', (event, d) => setHoveredItem({ type: 'node', data: d }))
      .on('mouseleave', () => setHoveredItem(null));

    // Node Outer Ring (Glow & Status)
    node
      .append('circle')
      .attr('r', (d) => (d.type === 'endpoint' ? 18 : d.type === 'user' ? 16 : 14))
      .attr('fill', (d) => {
        if (d.status === 'blocked') return 'rgba(239, 68, 68, 0.25)';
        if (d.status === 'flagged') return 'rgba(245, 158, 11, 0.25)';
        if (d.type === 'user') return 'rgba(14, 165, 233, 0.2)';
        if (d.type === 'endpoint') return 'rgba(16, 185, 129, 0.2)';
        return 'rgba(99, 102, 241, 0.2)';
      })
      .attr('stroke', (d) => {
        if (d.status === 'blocked') return '#ef4444';
        if (d.status === 'flagged') return '#f59e0b';
        if (d.type === 'user') return '#38bdf8';
        if (d.type === 'endpoint') return '#10b981';
        return '#818cf8';
      })
      .attr('stroke-width', (d) => (d.status === 'blocked' ? 3 : 1.5))
      .attr('filter', (d) => (d.status === 'blocked' ? 'url(#glow-red)' : 'url(#glow-cyan)'));

    // Node Center Symbol / Icon Shape
    node
      .append('circle')
      .attr('r', 7)
      .attr('fill', (d) => {
        if (d.status === 'blocked') return '#ef4444';
        if (d.status === 'flagged') return '#f59e0b';
        if (d.type === 'user') return '#0284c7';
        if (d.type === 'endpoint') return '#059669';
        return '#4f46e5';
      });

    // Node Labels
    node
      .append('text')
      .attr('dy', 28)
      .attr('text-anchor', 'middle')
      .attr('font-family', 'monospace')
      .attr('font-size', '10px')
      .attr('font-weight', '600')
      .attr('fill', (d) => (d.status === 'blocked' ? '#fca5a5' : '#e2e8f0'))
      .text((d) => d.label || d.id);

    // Node Subtitle (Type or Owner)
    node
      .append('text')
      .attr('dy', 40)
      .attr('text-anchor', 'middle')
      .attr('font-family', 'monospace')
      .attr('font-size', '8px')
      .attr('fill', '#94a3b8')
      .text((d) => {
        if (d.type === 'resource' && d.owners && d.owners.length > 0) return `Owner: ${d.owners.join(', ')}`;
        if (d.type === 'user') return d.role || 'user';
        if (d.type === 'endpoint') return d.resource ? `[${d.resource}]` : '';
        return '';
      });

    // Simulation Tick Updates
    simulation.on('tick', () => {
      linkLine
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      link
        .selectAll('.animate-pulse')
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      linkText
        .attr('x', (d) => (d.source.x + d.target.x) / 2)
        .attr('y', (d) => (d.source.y + d.target.y) / 2);

      node.attr('transform', (d) => `translate(${d.x},${d.y})`);
    });

    return () => {
      simulation.stop();
    };
  }, [nodes, links]);

  return (
    <div className="relative flex flex-col rounded-lg border border-white/10 bg-canvas-sunken/80 backdrop-blur-md overflow-hidden">
      {/* Graph Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-canvas/60 px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-accent">hub</span>
          <h3 className="font-display text-sm font-bold uppercase tracking-wider text-ink">
            Interactive Network Access Graph
          </h3>
          <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
            Live D3 NetworkX Map
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          {/* Search Box */}
          <div className="relative">
            <input
              type="text"
              placeholder="Search user / resource..."
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              className="w-44 rounded border border-canvas-line bg-canvas-sunken px-2.5 py-1 pl-7 font-mono text-[11px] text-ink placeholder:text-ink-faint focus:border-accent focus:outline-none"
            />
            <span className="material-symbols-outlined absolute left-1.5 top-1.5 text-[14px] text-ink-faint">
              search
            </span>
          </div>

          {/* Anomalies Filter Toggle */}
          <label className="flex cursor-pointer items-center gap-1.5 font-mono text-[11px] text-ink-muted">
            <input
              type="checkbox"
              checked={filterAnomalousOnly}
              onChange={(e) => setFilterAnomalousOnly(e.target.checked)}
              className="rounded border-canvas-line text-risk-danger focus:ring-risk-danger"
            />
            <span className={filterAnomalousOnly ? 'font-semibold text-risk-danger' : ''}>
              Flashing Anomalies Only
            </span>
          </label>
        </div>
      </div>

      {/* Legend & Stats Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/5 bg-canvas-raised/30 px-4 py-1.5 font-mono text-[10px] text-ink-faint">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400"></span>
            <span>User</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-emerald-400"></span>
            <span>API Endpoint</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-indigo-400"></span>
            <span>Resource Object</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-0.5 w-4 bg-sky-400"></span>
            <span>Legitimate Access</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-0.5 w-4 animate-pulse bg-risk-danger shadow-[0_0_8px_#ff0055]"></span>
            <span className="font-semibold text-risk-danger">Cross-Tenant BOLA (Flashing Red)</span>
          </div>
        </div>

        <div className="flex items-center gap-3">
          <span>Nodes: <strong className="text-ink">{nodes.length}</strong></span>
          <span>Edges: <strong className="text-ink">{links.length}</strong></span>
          {data?.stats?.cross_tenant_edge_count > 0 && (
            <span className="rounded bg-risk-danger-dim/60 px-1.5 py-0.5 font-bold text-risk-danger animate-pulse">
              ⚡ {data.stats.cross_tenant_edge_count} BOLA Anomalies
            </span>
          )}
        </div>
      </div>

      {/* Main SVG Graph Container */}
      <div ref={containerRef} className="relative h-[560px] w-full bg-canvas-sunken/90">
        <svg ref={svgRef} className="h-full w-full select-none" />

        {/* Hover Tooltip Overlay */}
        {hoveredItem && (
          <div className="pointer-events-none absolute right-4 top-4 z-20 max-w-xs rounded border border-white/20 bg-canvas/95 p-3 shadow-2xl backdrop-blur-md font-mono text-xs text-ink">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-bold uppercase tracking-wider text-accent">
                {hoveredItem.data.type} node
              </span>
              <span
                className={`rounded px-1.5 py-0.5 text-[9px] ${
                  hoveredItem.data.status === 'blocked'
                    ? 'bg-risk-danger/20 text-risk-danger'
                    : 'bg-emerald-500/20 text-emerald-400'
                }`}
              >
                {hoveredItem.data.status || 'active'}
              </span>
            </div>
            <div className="text-sm font-bold text-ink">{hoveredItem.data.label || hoveredItem.data.id}</div>
            {hoveredItem.data.owners && (
              <div className="mt-1 text-[11px] text-ink-muted">
                Authorized Owners: <span className="text-accent">{hoveredItem.data.owners.join(', ')}</span>
              </div>
            )}
            {hoveredItem.data.ml_risk !== undefined && (
              <div className="mt-1 text-[11px] text-ink-muted">
                ML Anomaly Risk: <span className="text-risk-danger font-bold">{hoveredItem.data.ml_risk}%</span>
              </div>
            )}
          </div>
        )}

        {/* Node Selection Inspector Modal/Card */}
        {selectedNode && (
          <div className="absolute left-4 bottom-4 z-20 max-w-sm rounded-lg border border-accent/40 bg-canvas/95 p-4 shadow-2xl backdrop-blur-md font-mono text-xs text-ink">
            <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
              <span className="font-bold text-accent">Selected Node Details</span>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-ink-faint hover:text-ink"
              >
                ✕
              </button>
            </div>
            <div className="space-y-1 text-[11px]">
              <div><strong className="text-ink-muted">ID:</strong> {selectedNode.id}</div>
              <div><strong className="text-ink-muted">Type:</strong> {selectedNode.type}</div>
              <div><strong className="text-ink-muted">Label:</strong> {selectedNode.label}</div>
              {selectedNode.resource && <div><strong className="text-ink-muted">Resource:</strong> {selectedNode.resource}</div>}
              {selectedNode.owners && (
                <div><strong className="text-ink-muted">Authorized Owners:</strong> {selectedNode.owners.join(', ')}</div>
              )}
              {selectedNode.status && (
                <div>
                  <strong className="text-ink-muted">Security Status:</strong>{' '}
                  <span className={selectedNode.status === 'blocked' ? 'text-risk-danger font-bold' : 'text-emerald-400'}>
                    {selectedNode.status.toUpperCase()}
                  </span>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
