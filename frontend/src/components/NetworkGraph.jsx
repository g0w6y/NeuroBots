import { useEffect, useRef, useState, useMemo, useCallback } from 'react';
import * as d3 from 'd3';

export default function NetworkGraph({ data, onSelectNode }) {
  const svgRef = useRef(null);
  const containerRef = useRef(null);
  const zoomBehaviorRef = useRef(null);
  const [selectedNode, setSelectedNode] = useState(null);
  const [hoveredItem, setHoveredItem] = useState(null);
  const [filterAnomalousOnly, setFilterAnomalousOnly] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [zoomScale, setZoomScale] = useState(1);

  const rawNodes = data?.nodes || [];
  const rawEdges = data?.edges || [];

  // Filter nodes & edges
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

    // Deep copy nodes for D3 force simulation
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

  // Smooth Reset Zoom handler
  const handleResetZoom = useCallback(() => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(750)
      .ease(d3.easeCubicInOut)
      .call(zoomBehaviorRef.current.transform, d3.zoomIdentity);
  }, []);

  const handleZoomIn = useCallback(() => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(350)
      .ease(d3.easeCubicOut)
      .call(zoomBehaviorRef.current.scaleBy, 1.3);
  }, []);

  const handleZoomOut = useCallback(() => {
    if (!svgRef.current || !zoomBehaviorRef.current) return;
    d3.select(svgRef.current)
      .transition()
      .duration(350)
      .ease(d3.easeCubicOut)
      .call(zoomBehaviorRef.current.scaleBy, 0.75);
  }, []);

  useEffect(() => {
    if (!svgRef.current || !containerRef.current) return;

    const width = containerRef.current.clientWidth || 800;
    const height = 580;

    const svg = d3.select(svgRef.current);
    svg.selectAll('*').remove();

    // Embedded CSS Styles & Animations for silky 60fps rendering
    const styleDef = svg.append('style').text(`
      @keyframes laserFlow {
        from { stroke-dashoffset: 24; }
        to { stroke-dashoffset: 0; }
      }
      @keyframes redPulseGlow {
        0%, 100% { stroke-opacity: 0.7; filter: drop-shadow(0 0 3px #ff0055); }
        50% { stroke-opacity: 1.0; filter: drop-shadow(0 0 10px #ff0055); }
      }
      @keyframes cyanParticleFlow {
        from { stroke-dashoffset: 20; }
        to { stroke-dashoffset: 0; }
      }
      .node-group circle.outer-ring {
        transition: r 0.3s cubic-bezier(0.34, 1.56, 0.64, 1), stroke-width 0.3s ease, filter 0.3s ease;
      }
      .node-group:hover circle.outer-ring {
        r: 21px;
        stroke-width: 2.5px;
        filter: drop-shadow(0 0 12px rgba(56, 189, 248, 0.8));
      }
      .node-group.status-blocked:hover circle.outer-ring {
        filter: drop-shadow(0 0 14px rgba(239, 68, 68, 0.9));
      }
      .edge-laser-anomaly {
        animation: laserFlow 0.8s linear infinite, redPulseGlow 1.8s ease-in-out infinite;
      }
      .edge-cyan-flow {
        animation: cyanParticleFlow 1.6s linear infinite;
      }
    `);

    // Define Filters & Arrow Markers
    const defs = svg.append('defs');

    // Glow filter for anomalous edges & blocked nodes
    const glowFilter = defs
      .append('filter')
      .attr('id', 'glow-red')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    glowFilter.append('feGaussianBlur').attr('stdDeviation', '4').attr('result', 'coloredBlur');
    const feMerge = glowFilter.append('feMerge');
    feMerge.append('feMergeNode').attr('in', 'coloredBlur');
    feMerge.append('feMergeNode').attr('in', 'SourceGraphic');

    // Cyan glow filter for normal active nodes
    const cyanFilter = defs
      .append('filter')
      .attr('id', 'glow-cyan')
      .attr('x', '-50%')
      .attr('y', '-50%')
      .attr('width', '200%')
      .attr('height', '200%');
    cyanFilter.append('feGaussianBlur').attr('stdDeviation', '3.5').attr('result', 'coloredBlur');
    const feMergeCyan = cyanFilter.append('feMerge');
    feMergeCyan.append('feMergeNode').attr('in', 'coloredBlur');
    feMergeCyan.append('feMergeNode').attr('in', 'SourceGraphic');

    // Arrow markers
    defs
      .append('marker')
      .attr('id', 'arrow-normal')
      .attr('viewBox', '0 -5 10 10')
      .attr('refX', 24)
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
      .attr('refX', 25)
      .attr('refY', 0)
      .attr('markerWidth', 7)
      .attr('markerHeight', 7)
      .attr('orient', 'auto')
      .append('path')
      .attr('d', 'M0,-5L10,0L0,5')
      .attr('fill', '#ff0055');

    // Root Group for Zoom
    const g = svg.append('g').attr('class', 'graph-root-group');

    // Zoom behavior with smooth scale limits
    const zoom = d3
      .zoom()
      .scaleExtent([0.25, 4])
      .on('zoom', (event) => {
        g.attr('transform', event.transform);
        setZoomScale(event.transform.k);
      });

    zoomBehaviorRef.current = zoom;
    svg.call(zoom);

    // Bipartite/Tripartite layered layout initial coordinates:
    // Users (Left X ~ 18%) -> Endpoints (Middle X ~ 50%) -> Resources (Right X ~ 82%)
    nodes.forEach((node) => {
      if (node.type === 'user') {
        node.x = width * 0.18 + (Math.random() - 0.5) * 40;
        node.y = height * 0.5 + (Math.random() - 0.5) * 320;
      } else if (node.type === 'endpoint') {
        node.x = width * 0.5 + (Math.random() - 0.5) * 40;
        node.y = height * 0.5 + (Math.random() - 0.5) * 220;
      } else {
        node.x = width * 0.82 + (Math.random() - 0.5) * 40;
        node.y = height * 0.5 + (Math.random() - 0.5) * 320;
      }
    });

    // Silky Physics Force Simulation Tuning:
    // Low alphaDecay (0.018) for ultra-smooth transition + velocityDecay (0.32) to eliminate jitter
    const simulation = d3
      .forceSimulation(nodes)
      .alphaDecay(0.018)
      .velocityDecay(0.32)
      .force(
        'link',
        d3
          .forceLink(links)
          .id((d) => d.id)
          .distance((d) => (d.is_anomalous ? 160 : 130))
          .strength(0.6)
      )
      .force('charge', d3.forceManyBody().strength(-280))
      .force('collision', d3.forceCollide().radius(40))
      .force(
        'x',
        d3
          .forceX((d) => {
            if (d.type === 'user') return width * 0.18;
            if (d.type === 'endpoint') return width * 0.5;
            return width * 0.82;
          })
          .strength(0.45)
      )
      .force('y', d3.forceY(height * 0.5).strength(0.12));

    // Render Edges (Links)
    const linkGroup = g.append('g').attr('class', 'links');
    const link = linkGroup
      .selectAll('g')
      .data(links)
      .enter()
      .append('g')
      .attr('class', 'link-container');

    // Base background edge line
    const linkLine = link
      .append('line')
      .attr('stroke', (d) => (d.is_cross_tenant || d.is_anomalous ? '#ff0055' : '#1e293b'))
      .attr('stroke-width', (d) => (d.is_cross_tenant || d.is_anomalous ? 2.5 : 1.2))
      .attr('stroke-opacity', (d) => (d.is_cross_tenant || d.is_anomalous ? 0.9 : 0.6))
      .attr('marker-end', (d) => (d.is_cross_tenant || d.is_anomalous ? 'url(#arrow-anomaly)' : 'url(#arrow-normal)'));

    // Animated overlay line: Legitimate traffic flows cyan dots, Anomalous traffic flows laser red!
    const animatedFlowOverlay = link
      .append('line')
      .attr('class', (d) => (d.is_cross_tenant || d.is_anomalous ? 'edge-laser-anomaly' : 'edge-cyan-flow'))
      .attr('stroke', (d) => (d.is_cross_tenant || d.is_anomalous ? '#ff2a6d' : '#38bdf8'))
      .attr('stroke-width', (d) => (d.is_cross_tenant || d.is_anomalous ? 3.5 : 1.5))
      .attr('stroke-dasharray', (d) => (d.is_cross_tenant || d.is_anomalous ? '8 6' : '3 9'))
      .attr('stroke-linecap', 'round')
      .attr('opacity', 0.85);

    // Edge Labels
    const linkText = link
      .append('text')
      .attr('font-size', '9px')
      .attr('font-family', 'monospace')
      .attr('font-weight', '600')
      .attr('fill', (d) => (d.is_cross_tenant || d.is_anomalous ? '#ff0055' : '#64748b'))
      .attr('text-anchor', 'middle')
      .attr('dy', -5)
      .text((d) => (d.is_cross_tenant ? '⚡ CROSS-TENANT BOLA' : d.label || ''));

    // Render Nodes
    const nodeGroup = g.append('g').attr('class', 'nodes');
    const node = nodeGroup
      .selectAll('g')
      .data(nodes)
      .enter()
      .append('g')
      .attr('class', (d) => `node-group cursor-pointer ${d.status === 'blocked' ? 'status-blocked' : ''}`)
      .call(
        d3
          .drag()
          .on('start', (event, d) => {
            if (!event.active) simulation.alphaTarget(0.2).restart();
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

    // Node Outer Ring (Glowing Circle)
    node
      .append('circle')
      .attr('class', 'outer-ring')
      .attr('r', (d) => (d.type === 'endpoint' ? 17 : d.type === 'user' ? 15 : 13))
      .attr('fill', (d) => {
        if (d.status === 'blocked') return 'rgba(239, 68, 68, 0.2)';
        if (d.status === 'flagged') return 'rgba(245, 158, 11, 0.2)';
        if (d.type === 'user') return 'rgba(14, 165, 233, 0.18)';
        if (d.type === 'endpoint') return 'rgba(16, 185, 129, 0.18)';
        return 'rgba(99, 102, 241, 0.18)';
      })
      .attr('stroke', (d) => {
        if (d.status === 'blocked') return '#ef4444';
        if (d.status === 'flagged') return '#f59e0b';
        if (d.type === 'user') return '#38bdf8';
        if (d.type === 'endpoint') return '#10b981';
        return '#818cf8';
      })
      .attr('stroke-width', (d) => (d.status === 'blocked' ? 2.5 : 1.5))
      .attr('filter', (d) => (d.status === 'blocked' ? 'url(#glow-red)' : 'url(#glow-cyan)'));

    // Node Core Icon Solid Circle
    node
      .append('circle')
      .attr('r', 6)
      .attr('fill', (d) => {
        if (d.status === 'blocked') return '#ef4444';
        if (d.status === 'flagged') return '#f59e0b';
        if (d.type === 'user') return '#0284c7';
        if (d.type === 'endpoint') return '#059669';
        return '#4f46e5';
      });

    // Node Title Label
    node
      .append('text')
      .attr('dy', 27)
      .attr('text-anchor', 'middle')
      .attr('font-family', 'monospace')
      .attr('font-size', '10px')
      .attr('font-weight', '600')
      .attr('fill', (d) => (d.status === 'blocked' ? '#fca5a5' : '#e2e8f0'))
      .text((d) => d.label || d.id);

    // Node Subtitle Label
    node
      .append('text')
      .attr('dy', 39)
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

    // Simulation Tick Listener with Smooth Coordinate Updates
    simulation.on('tick', () => {
      linkLine
        .attr('x1', (d) => d.source.x)
        .attr('y1', (d) => d.source.y)
        .attr('x2', (d) => d.target.x)
        .attr('y2', (d) => d.target.y);

      animatedFlowOverlay
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
    <div className="relative flex flex-col rounded-lg border border-white/10 bg-canvas-sunken/80 backdrop-blur-md overflow-hidden shadow-2xl">
      {/* Graph Header Controls */}
      <div className="flex flex-wrap items-center justify-between gap-3 border-b border-white/10 bg-canvas/60 px-4 py-3">
        <div className="flex items-center gap-2">
          <span className="material-symbols-outlined text-accent animate-pulse">hub</span>
          <h3 className="font-display text-sm font-bold uppercase tracking-wider text-ink">
            Interactive Network Access Graph
          </h3>
          <span className="rounded bg-accent/10 px-2 py-0.5 font-mono text-[10px] text-accent">
            Live 60fps NetworkX Map
          </span>
        </div>

        <div className="flex flex-wrap items-center gap-3 text-xs">
          {/* Zoom Buttons Toolbar */}
          <div className="flex items-center rounded border border-canvas-line bg-canvas-sunken font-mono text-xs">
            <button
              type="button"
              onClick={handleZoomIn}
              title="Zoom In"
              className="px-2 py-1 text-ink-muted hover:bg-canvas-raised hover:text-ink transition-colors"
            >
              +
            </button>
            <span className="border-x border-canvas-line px-2 py-1 text-[10px] text-ink-faint tabular-nums">
              {Math.round(zoomScale * 100)}%
            </span>
            <button
              type="button"
              onClick={handleZoomOut}
              title="Zoom Out"
              className="px-2 py-1 text-ink-muted hover:bg-canvas-raised hover:text-ink transition-colors"
            >
              −
            </button>
            <button
              type="button"
              onClick={handleResetZoom}
              title="Reset View"
              className="border-l border-canvas-line px-2 py-1 text-[10px] uppercase text-accent hover:bg-canvas-raised transition-colors"
            >
              Reset
            </button>
          </div>

          {/* Search Input */}
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

          {/* Anomalies Only Toggle */}
          <label className="flex cursor-pointer items-center gap-1.5 font-mono text-[11px] text-ink-muted">
            <input
              type="checkbox"
              checked={filterAnomalousOnly}
              onChange={(e) => setFilterAnomalousOnly(e.target.checked)}
              className="rounded border-canvas-line text-risk-danger focus:ring-risk-danger"
            />
            <span className={filterAnomalousOnly ? 'font-semibold text-risk-danger' : ''}>
              Anomalies Only
            </span>
          </label>
        </div>
      </div>

      {/* Legend & Telemetry Banner */}
      <div className="flex flex-wrap items-center justify-between gap-4 border-b border-white/5 bg-canvas-raised/30 px-4 py-1.5 font-mono text-[10px] text-ink-faint">
        <div className="flex items-center gap-4">
          <div className="flex items-center gap-1.5">
            <span className="h-2.5 w-2.5 rounded-full bg-sky-400"></span>
            <span>User Node</span>
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
            <span>Legitimate Flow</span>
          </div>
          <div className="flex items-center gap-1.5">
            <span className="h-0.5 w-4 bg-risk-danger shadow-[0_0_8px_#ff0055]"></span>
            <span className="font-semibold text-risk-danger">Cross-Tenant BOLA Laser</span>
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

      {/* Main Graph SVG Canvas */}
      <div ref={containerRef} className="relative h-[580px] w-full bg-canvas-sunken/90">
        <svg ref={svgRef} className="h-full w-full select-none" />

        {/* Hover Tooltip Card */}
        {hoveredItem && (
          <div className="pointer-events-none absolute right-4 top-4 z-20 max-w-xs rounded border border-white/20 bg-canvas/95 p-3 shadow-2xl backdrop-blur-md font-mono text-xs text-ink transition-opacity duration-200">
            <div className="mb-1 flex items-center justify-between gap-2">
              <span className="font-bold uppercase tracking-wider text-accent">
                {hoveredItem.data.type} node
              </span>
              <span
                className={`rounded px-1.5 py-0.5 text-[9px] ${
                  hoveredItem.data.status === 'blocked'
                    ? 'bg-risk-danger/20 text-risk-danger font-bold'
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

        {/* Selected Node Inspector Modal */}
        {selectedNode && (
          <div className="absolute left-4 bottom-4 z-20 max-w-sm rounded-lg border border-accent/40 bg-canvas/95 p-4 shadow-2xl backdrop-blur-md font-mono text-xs text-ink transition-all">
            <div className="flex items-center justify-between border-b border-white/10 pb-2 mb-2">
              <span className="font-bold text-accent">Selected Node Details</span>
              <button
                type="button"
                onClick={() => setSelectedNode(null)}
                className="text-ink-faint hover:text-ink transition-colors"
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
