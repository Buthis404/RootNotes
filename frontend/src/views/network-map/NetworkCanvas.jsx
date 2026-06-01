/**
 * Network canvas — SVG topology rendering, node/edge interaction, drag & drop.
 *
 * Extracted from NetworkView.jsx.
 */
import { useCallback, useEffect, useMemo, useRef, useState } from 'react';
import PropTypes from 'prop-types';
import Icon from '../../components/Icon.jsx';
import { NODE_STATUS } from '../../constants.js';
import { api } from '../../api.js';
import { isAttackerHost, HOST_ROLES } from '../../utils/hostMeta.js';
import AddFromProjectPanel from './AddFromProjectPanel.jsx';
import { NodeShape, guessNodeType, inferAllRoles } from './NodeVisuals.jsx';
import { REGION_FILL, REGION_STROKE } from './constants.js';
import { TRANSPORT_COLORS, buildAttackAdj, computeAttackPathSet, edgeStyle, findAttackerNodeIds, renderRoleBadges } from './GraphAlgorithms.jsx';
import { NetworkInspector } from './NetworkInspector.jsx';

function _normalizeNet(n) {
  if (!n) return { nodes: [], edges: [], regions: [] };
  return {
    ...n,
    nodes: n.nodes || n.nodes_json || [],
    edges: n.edges || n.edges_json || [],
    regions: n.regions || n.regions_json || [],
  };
}

function _pivotRank(type) {
  if (type === 'socks5' || type === 'socks4') {
    return 2;
  }
  if (type === 'route') {
    return 1;
  }
  return 0;
}

async function _handleConnectEdges({ connecting, selectedNodeIds, nid, edges, projectId, net, newLocalMutationId, markLocalOp, emit }) {
  const sourceNodes = selectedNodeIds.length > 0 ? selectedNodeIds : [connecting];
  const newEdges = sourceNodes
    .filter(srcId => srcId !== nid)
    .map(srcId => ({
      from_node_id: srcId,
      to_node_id: nid,
      label: 'link',
      style: 'normal'
    }));
  if (newEdges.length > 0) {
    const created = await Promise.all(newEdges.map(async (edge) => {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      const result = await api.createNetworkLink(projectId, { network_id: net.id, ...edge, client_mutation_id: lid });
      return result.link;
    })).catch(() => []);
    if (created.length > 0) emit({ edges: [...edges, ...created] }, { persist: false });
  }
}

function _cleanupLocalMutation(nodeId, ref) {
  setTimeout(() => { ref.current.delete(nodeId); }, 500);
}

function _applyIncomingNet({ net, cloneNet, sameNet, draftNetRef, setDraftNet, netIdRef, setHistoryState, localMutationIdsRef, pendingServerNetRef, draggingNode, draggingRegion, resizingRegion, pendingNodeDragRef, interactionStartRef }) {
  const next = _normalizeNet(net);
  const nextClone = cloneNet(next);
  if (netIdRef.current !== (net?.id || null)) {
    netIdRef.current = net?.id || null;
    draftNetRef.current = nextClone;
    setDraftNet(nextClone);
    interactionStartRef.current = null;
    setHistoryState({ past: [], future: [] });
    localMutationIdsRef.current.clear();
    pendingServerNetRef.current = null;
    return;
  }
  if (sameNet(nextClone, draftNetRef.current)) {
    return;
  }

  if (draggingNode || draggingRegion || resizingRegion || pendingNodeDragRef.current) {
    console.log('[NET-UE] deferred (drag active)', { draggingNode, pending: !!pendingNodeDragRef.current });
    pendingServerNetRef.current = nextClone;
    return;
  }

  console.log('[NET-UE] applying server net', {
    serverNodePositions: (nextClone.nodes||[]).slice(0,3).map(n => ({ id: n.id, x: n.x, y: n.y })),
    draftNodePositions: (draftNetRef.current.nodes||[]).slice(0,3).map(n => ({ id: n.id, x: n.x, y: n.y })),
  });

  const draftNodes = draftNetRef.current.nodes || [];
  const serverNodes = nextClone.nodes || [];
  if (draftNodes.length && serverNodes.length) {
    for (const sn of serverNodes) {
      const dn = draftNodes.find(n => n.id === sn.id);
      if (dn) {
        sn.x = dn.x;
        sn.y = dn.y;
        if (dn.manually_positioned !== undefined) {
          sn.manually_positioned = dn.manually_positioned;
        }
      }
    }
  }

  setHistoryState(state => ({ past: [...state.past, cloneNet(draftNetRef.current)], future: [] }));
  draftNetRef.current = nextClone;
  setDraftNet(nextClone);
  interactionStartRef.current = null;
}

function _isInteractionActive(draggingNode, draggingRegion, resizingRegion, draggingCanvas, selectBox, pendingNodeDragRef) {
  return !!(draggingNode || draggingRegion || resizingRegion || draggingCanvas || selectBox || pendingNodeDragRef.current);
}

function _handleSelectBoxMove(e, selectBox, getSVGPt, nodes, setSelectBox, setSelectedNodeIds) {
  const pt = getSVGPt(e);
  setSelectBox(prev => ({ ...prev, endX: pt.x, endY: pt.y }));
  const minX = Math.min(selectBox.startX, pt.x);
  const maxX = Math.max(selectBox.startX, pt.x);
  const minY = Math.min(selectBox.startY, pt.y);
  const maxY = Math.max(selectBox.startY, pt.y);
  const nodesInBox = nodes.filter(n =>
    n.x >= minX && n.x <= maxX && n.y >= minY && n.y <= maxY
  );
  setSelectedNodeIds(nodesInBox.map(n => n.id));
}

function _tryPromotePendingDrag(e, pendingNodeDragRef, dragOffset, cloneNet, draftNetRef, interactionStartRef, setDraggingNode) {
  const pending = pendingNodeDragRef.current;
  const dxClient = e.clientX - pending.startClientX;
  const dyClient = e.clientY - pending.startClientY;
  if (Math.hypot(dxClient, dyClient) >= 4) {
    dragOffset.current = { x: pending.offsetX, y: pending.offsetY };
    interactionStartRef.current = cloneNet(draftNetRef.current);
    setDraggingNode(pending.nid);
  }
}

function _handleNodeDragMove(e, draggingNode, dragOffset, getSVGPt, { draftNetRef, selectedNodeSet, emit, syncDraggedNodePositions }) {
  const pt = getSVGPt(e);
  const liveNodes = draftNetRef.current.nodes || [];
  const lead = liveNodes.find(n => n.id === draggingNode);
  const dx = pt.x - dragOffset.current.x - lead.x;
  const dy = pt.y - dragOffset.current.y - lead.y;
  emit({ nodes: liveNodes.map(n => selectedNodeSet.has(n.id) ? { ...n, x: n.x + dx, y: n.y + dy } : n) }, { history: 'skip', persist: false });
  syncDraggedNodePositions(selectedNodeSet);
}

function _handleRegionDragMove(e, draggingRegion, dragOffset, getSVGPt, draftNetRef, emit) {
  const pt = getSVGPt(e);
  const liveRegions = draftNetRef.current.regions || [];
  const region = liveRegions.find(r => r.id === draggingRegion);
  emit({ regions: liveRegions.map(r => r.id === draggingRegion ? { ...r, x: pt.x - dragOffset.current.x, y: pt.y - dragOffset.current.y, w: region.w, h: region.h } : r) }, { history: 'skip', persist: false });
}

function _handleRegionResizeMove(e, resizingRegion, getSVGPt, draftNetRef, emit) {
  const pt = getSVGPt(e);
  const liveRegions = draftNetRef.current.regions || [];
  const region = liveRegions.find(r => r.id === resizingRegion.id);
  if (!region) {
    return;
  }
  const min = 40;
  let patch = {};
  if (resizingRegion.corner === 'se') {
    patch = { w: Math.max(min, pt.x - region.x), h: Math.max(min, pt.y - region.y) };
  } else if (resizingRegion.corner === 'sw') {
    const newX = Math.min(region.x + region.w - min, pt.x);
    patch = { x: newX, w: Math.max(min, region.x + region.w - newX), h: Math.max(min, pt.y - region.y) };
  } else if (resizingRegion.corner === 'ne') {
    const newY = Math.min(region.y + region.h - min, pt.y);
    patch = { y: newY, h: Math.max(min, region.y + region.h - newY), w: Math.max(min, pt.x - region.x) };
  } else if (resizingRegion.corner === 'nw') {
    const newX = Math.min(region.x + region.w - min, pt.x);
    const newY = Math.min(region.y + region.h - min, pt.y);
    patch = { x: newX, y: newY, w: Math.max(min, region.x + region.w - newX), h: Math.max(min, region.y + region.h - newY) };
  }
  emit({ regions: liveRegions.map(r => r.id === region.id ? { ...r, ...patch } : r) }, { history: 'skip', persist: false });
}

function _handleCanvasPanMove(e, draggingCanvas, panRef, canvasGroupRef, zoom) {
  const newPan = { x: e.clientX - draggingCanvas.startX, y: e.clientY - draggingCanvas.startY };
  panRef.current = newPan;
  if (canvasGroupRef.current) {
    canvasGroupRef.current.setAttribute('transform', `translate(${newPan.x},${newPan.y}) scale(${zoom})`);
  }
}

function _finalizeDragInteraction(draggingNode, draggingRegion, resizingRegion, { interactionStartRef, draftNetRef, pushHistorySnapshot, syncDraggedNodePositions, selectedNodeSet, newLocalMutationId, markLocalOp, projectId, net, flushNetUpdate }) {
  if (!interactionStartRef.current) return;
  pushHistorySnapshot(interactionStartRef.current, draftNetRef.current);
  interactionStartRef.current = null;
  if (draggingNode) {
    syncDraggedNodePositions(selectedNodeSet, { force: true });
  } else if (draggingRegion || resizingRegion) {
    const regionId = draggingRegion || resizingRegion?.id;
    const region = draftNetRef.current.regions?.find(item => item.id === regionId);
    if (region) {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      api.updateNetworkRegion(projectId, region.id, net.id, {
        x: region.x, y: region.y, w: region.w, h: region.h,
        client_mutation_id: lid,
      }).catch(() => {});
    }
  } else {
    flushNetUpdate();
  }
}

function _applyPendingServerNet(pendingServerNetRef, draftNetRef, setDraftNet) {
  const serverClone = pendingServerNetRef.current;
  pendingServerNetRef.current = null;
  const draftNodes = draftNetRef.current.nodes || [];
  const serverNodes = serverClone.nodes || [];
  if (draftNodes.length && serverNodes.length) {
    for (const sn of serverNodes) {
      const dn = draftNodes.find(n => n.id === sn.id);
      if (dn) {
        sn.x = dn.x;
        sn.y = dn.y;
        if (dn.manually_positioned !== undefined) {
          sn.manually_positioned = dn.manually_positioned;
        }
      }
    }
  }
  draftNetRef.current = serverClone;
  setDraftNet(serverClone);
}

function _sameItems(an, bn) {
  for (let i = 0; i < an.length; i++) {
    if (an[i].id !== bn[i].id) return false;
    const ak = Object.keys(an[i]), bk = Object.keys(bn[i]);
    if (ak.length !== bk.length) return false;
    for (const k of ak) { if (an[i][k] !== bn[i][k]) return false; }
    for (const k of bk) { if (!(k in an[i])) return false; }
  }
  return true;
}

function _sameCollections(a, b) {
  if ((a?.length || 0) !== (b?.length || 0)) return false;
  if (a && a.length > 0) return _sameItems(a, b);
  return true;
}

function _sameMeta(a, b) {
  const skip = new Set(['nodes', 'edges', 'regions']);
  const ak = Object.keys(a || {}).filter(k => !skip.has(k));
  const bk = Object.keys(b || {}).filter(k => !skip.has(k));
  if (ak.length !== bk.length) return false;
  for (const k of ak) { if (a[k] !== b[k]) return false; }
  return true;
}

export default function NetworkCanvas({ projectId, net, onUpdate, onCreateHost, onUpdateHost, onSyncHostByIp, accent, accentGreen, hosts, onAddActivity, onUpdateActivity, onDeleteActivity, markLocalOp, animateLinks, overlayData, accessOverlay, overlayMode, pivots = [], projectHosts = [], onDeletePivot, onUpdatePivot, onAddPivotForHost }) {
  const [selectedNodeIds, setSelectedNodeIds] = useState([]);
  const [selectedRegionId, setSelectedRegionId] = useState(null);
  const [connecting, setConnecting] = useState(null);
  // overlayData presence drives visibility — no separate toggle needed
  const showOverlay = !!overlayData && overlayMode !== 'none';
  const [pan, setPan] = useState({ x: 40, y: 40 });
  const [zoom, setZoom] = useState(1);
  const [draggingNode, setDraggingNode] = useState(null);
  const [draggingRegion, setDraggingRegion] = useState(null);
  const [resizingRegion, setResizingRegion] = useState(null);
  const [draggingCanvas, setDraggingCanvas] = useState(null);
  const [showAddFromProject, setShowAddFromProject] = useState(false);
  const [showAttackAnalyzer, setShowAttackAnalyzer] = useState(false);
  const [showCreateNode, setShowCreateNode] = useState(false);
  const [nodeDraft, setNodeDraft] = useState({ ip: '', hostname: '', os: 'Unknown', role: 'unknown', status: 'unknown', domain: '' });
  const [edgeMenu, setEdgeMenu] = useState(null);
  const [regionEditMode, setRegionEditMode] = useState(false);
  const [selectBox, setSelectBox] = useState(null);
  const [analysisCreds, setAnalysisCreds] = useState(null);
  const [analysisCredsLoading, setAnalysisCredsLoading] = useState(false);
  const [historyState, setHistoryState] = useState({ past: [], future: [] });

  const svgRef = useRef();
  const dragOffset = useRef({ x: 0, y: 0 });
  const canvasGroupRef = useRef(null);
  const panRef = useRef({ x: 40, y: 40 });
  const commitTimerRef = useRef(null);
  const hostSyncTimersRef = useRef({});
  const pendingHostPatchesRef = useRef({});
  const pendingHostNodesRef = useRef({});
  const renderCountRef = useRef(0);
  const interactionStartRef = useRef(null);
  const lastPositionSyncRef = useRef(0);
  const netIdRef = useRef(net?.id || null);
  const pendingNodeDragRef = useRef(null);
  const draftNetRef = useRef(_normalizeNet(net));

  renderCountRef.current += 1;

  const [draftNet, setDraftNet] = useState(() => _normalizeNet(net));

  const localMutationIdsRef = useRef(new Set());

  const cloneNet = useCallback((value) => JSON.parse(JSON.stringify(value || { nodes: [], edges: [], regions: [] })), []);
  const sameNet = useCallback((a, b) => {
    if (a === b) return true;
    return _sameCollections(a?.nodes, b?.nodes)
      && _sameCollections(a?.edges, b?.edges)
      && _sameCollections(a?.regions, b?.regions)
      && _sameMeta(a, b);
  }, []);
  const pendingServerNetRef = useRef(null);

  useEffect(() => {
    _applyIncomingNet({ net, cloneNet, sameNet, draftNetRef, setDraftNet, netIdRef, setHistoryState, localMutationIdsRef, pendingServerNetRef, draggingNode, draggingRegion, resizingRegion, pendingNodeDragRef, interactionStartRef });
  }, [cloneNet, net, sameNet, draggingNode, draggingRegion, resizingRegion]);

  const nodes = draftNet?.nodes || [];
  const edges = draftNet?.edges || [];
  const regions = draftNet?.regions || [];

  const flushNetUpdate = useCallback((next = draftNetRef.current) => {
    if (commitTimerRef.current) {
      clearTimeout(commitTimerRef.current);
      commitTimerRef.current = null;
    }
    onUpdate(next);
  }, [onUpdate]);

  const pushHistorySnapshot = useCallback((previous, next) => {
    if (sameNet(previous, next)) {
      return;
    }
    setHistoryState(state => ({
      past: [...state.past, cloneNet(previous)],
      future: [],
    }));
  }, [cloneNet, sameNet]);

  const applySnapshot = useCallback((snapshot) => {
    if (commitTimerRef.current) {
      clearTimeout(commitTimerRef.current);
      commitTimerRef.current = null;
    }
    const next = cloneNet(snapshot);
    draftNetRef.current = next;
    setDraftNet(next);
    onUpdate(next);
  }, [cloneNet, onUpdate]);

  const emit = useCallback((patch, { immediate = false, history = 'push', persist = true } = {}) => {
    const prev = draftNetRef.current || { nodes: [], edges: [], regions: [] };
    const next = { ...prev, ...patch };
    if (history === 'push') {
      pushHistorySnapshot(prev, next);
    }
    draftNetRef.current = next;
    setDraftNet(next);
    if (persist) {
      if (commitTimerRef.current) {
        clearTimeout(commitTimerRef.current);
      }
      if (immediate) {
        queueMicrotask(() => onUpdate(next));
      } else {
        commitTimerRef.current = setTimeout(() => {
          commitTimerRef.current = null;
          onUpdate(draftNetRef.current);
        }, 240);
      }
    }
  }, [onUpdate, pushHistorySnapshot]);

  let _uidSeq = 0;
  const _uid = () => `nm_${Date.now().toString(36)}_${(++_uidSeq).toString(36)}`;
  const newLocalMutationId = useCallback(() => _uid(), []);

  // O(1) lookups — avoid O(n) find() in render loops
  const nodeById = useMemo(() => new Map(nodes.map(n => [n.id, n])), [nodes]);
  const hostById = useMemo(() => new Map((hosts || []).map(h => [h.id, h])), [hosts]);

  // Viewport culling — only render nodes/edges visible on screen (+buffer)
  const { visibleNodes, visibleEdges } = useMemo(() => {
    const el = svgRef.current;
    if (!el) return { visibleNodes: nodes, visibleEdges: edges };
    const { width, height } = el.getBoundingClientRect();
    const buf = 250;
    const L = (-pan.x - buf) / zoom;
    const T = (-pan.y - buf) / zoom;
    const R = (width  - pan.x + buf) / zoom;
    const B = (height - pan.y + buf) / zoom;
    const vn = nodes.filter(n => n.x > L && n.x < R && n.y > T && n.y < B);
    const vnSet = new Set(vn.map(n => n.id));
    const ve = edges.filter(e => vnSet.has(e.from) || vnSet.has(e.to));
    return { visibleNodes: vn, visibleEdges: ve };
  }, [nodes, edges, pan, zoom]);

  // Pre-compute role badges once per nodes change — not per render
  const roleBadgesByNodeId = useMemo(() => {
    const m = new Map();
    nodes.forEach(node => {
      const host = hostById.get(node.host_id);
      m.set(node.id, inferAllRoles(host || (node.role ? { role: node.role, tags: [], ports: node.ports || [] } : null)));
    });
    return m;
  }, [nodes, hostById]);

  // pivot type per host_id: socks5 > route > other
  const pivotByHostId = useMemo(() => {
    const m = new Map();
    for (const p of pivots) {
      if (!p.pivot_host_id || p.status !== 'active') {
        continue;
      }
      const existing = m.get(p.pivot_host_id);
      const rank = _pivotRank(p.pivot_type);
      if (!existing || rank > existing.rank) m.set(p.pivot_host_id, { type: p.pivot_type, route_cidr: p.route_cidr, rank });
    }
    return m;
  }, [pivots]);

  const selectedNodeSet = useMemo(() => new Set(selectedNodeIds), [selectedNodeIds]);
  const selectedNode = useMemo(() => {
    if (selectedNodeIds.length !== 1) {
      return null;
    }
    return nodeById.get(selectedNodeIds[0]) ?? null;
  }, [selectedNodeIds, nodeById]);

  const attackPathSet = useMemo(() => {
    if (!showOverlay || selectedNodeIds.length === 0) {
      return null;
    }
    const adj = buildAttackAdj(edges);
    const attackerNodeIds = findAttackerNodeIds(nodes, hosts);
    return computeAttackPathSet(adj, selectedNodeIds, selectedNodeSet, attackerNodeIds);
  }, [showOverlay, selectedNodeIds, selectedNodeSet, nodes, edges, hosts]);
  const selectedRegion = regions.find(r => r.id === selectedRegionId) || null;
  const hostObj = useMemo(() => {
    if (!selectedNode) {
      return null;
    }
    if (selectedNode.host_id) {
      return (hosts || []).find(h => h.id === selectedNode.host_id) || null;
    }
    let nodeIps = [];
    if (selectedNode.ips?.length > 0) nodeIps = selectedNode.ips;
    else if (selectedNode.ip) nodeIps = [selectedNode.ip];
    return (hosts || []).find(h => nodeIps.includes(h.ip)) || null;
  }, [selectedNode, hosts]);

  useEffect(() => {
    setSelectedNodeIds(prev => prev.filter(id => nodeById.has(id)));
    if (selectedRegionId && !regions.some(region => region.id === selectedRegionId)) {
      setSelectedRegionId(null);
    }
  }, [nodeById, regions, selectedRegionId]);

  useEffect(() => { setSelectedNodeIds([]); setSelectedRegionId(null); setConnecting(null); setEdgeMenu(null); }, [net?.id]);
  const nodesRef = useRef(nodes);
  useEffect(() => {
    nodesRef.current = nodes;
  }, [nodes]);

  const onKeyDown = useCallback((e) => {
    const key = e.key.toLowerCase();
    if ((e.ctrlKey || e.metaKey) && !e.shiftKey && key === 'z') {
      e.preventDefault();
      setHistoryState(state => {
        if (!state.past.length) {
          return state;
        }
        const previous = state.past[state.past.length - 1];
        const current = cloneNet(draftNetRef.current);
        queueMicrotask(() => applySnapshot(previous));
        return { past: state.past.slice(0, -1), future: [current, ...state.future] };
      });
      return;
    }
    if ((e.ctrlKey || e.metaKey) && ((e.shiftKey && key === 'z') || key === 'y')) {
      e.preventDefault();
      setHistoryState(state => {
        if (!state.future.length) {
          return state;
        }
        const next = state.future[0];
        const current = cloneNet(draftNetRef.current);
        queueMicrotask(() => applySnapshot(next));
        return { past: [...state.past, current], future: state.future.slice(1) };
      });
      return;
    }
    if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'a') {
      e.preventDefault();
      setSelectedNodeIds(nodesRef.current.map(n => n.id));
      setSelectedRegionId(null);
    }
    if (e.key === 'Escape') {
      setSelectedNodeIds([]);
      setSelectedRegionId(null);
      setConnecting(null);
      setEdgeMenu(null);
    }
  }, [applySnapshot, cloneNet]);

  useEffect(() => {
    globalThis.addEventListener('keydown', onKeyDown);
    return () => globalThis.removeEventListener('keydown', onKeyDown);
  }, [onKeyDown]);

  const getSVGPt = useCallback((e) => {
    const r = svgRef.current.getBoundingClientRect();
    return { x: (e.clientX - r.left - pan.x) / zoom, y: (e.clientY - r.top - pan.y) / zoom };
  }, [pan.x, pan.y, zoom]);

  const flushHostSync = useCallback(async (key) => {
    const patch = pendingHostPatchesRef.current[key];
    const node = pendingHostNodesRef.current[key];
    delete pendingHostPatchesRef.current[key];
    delete pendingHostNodesRef.current[key];
    delete hostSyncTimersRef.current[key];
    if (!patch || !node) {
      return;
    }
    const linkedHost = node.host_id ? hosts.find(h => h.id === node.host_id) : null;
    if (linkedHost && Object.keys(patch).length) {
      await onUpdateHost?.(linkedHost.id, patch);
    } else if (node.ip && Object.keys(patch).length) {
      await onSyncHostByIp?.(node.ip, patch);
    }
  }, [hosts, onSyncHostByIp, onUpdateHost]);

  const syncDraggedNodePositions = useCallback((nodeIds, { force = false } = {}) => {
    const now = Date.now();
    if (!force && now - lastPositionSyncRef.current < 140) {
      return;
    }
    lastPositionSyncRef.current = now;
    const movedNodes = (draftNetRef.current.nodes || []).filter(item => nodeIds.has(item.id));
    movedNodes.forEach((node) => {
      localMutationIdsRef.current.add(node.id);
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      api.updateNetworkNodePosition(projectId, node.id, net.id, {
        x: node.x,
        y: node.y,
        manually_positioned: true,
        client_mutation_id: lid,
      }).then(() => _cleanupLocalMutation(node.id, localMutationIdsRef)).catch(() => {});
    });
  }, [markLocalOp, net.id, newLocalMutationId, projectId]);

  const scheduleHostSync = useCallback((node, hostPatch) => {
    const key = node?.host_id || node?.ip;
    if (!key || !hostPatch || !Object.keys(hostPatch).length) {
      return;
    }
    pendingHostPatchesRef.current[key] = { ...pendingHostPatchesRef.current[key], ...hostPatch };
    pendingHostNodesRef.current[key] = { ...node, ...hostPatch };
    if (hostSyncTimersRef.current[key]) {
      clearTimeout(hostSyncTimersRef.current[key]);
    }
    hostSyncTimersRef.current[key] = setTimeout(() => {
      flushHostSync(key).catch(() => {});
    }, 350);
  }, [flushHostSync]);

  const updateNode = useCallback((id, patch) => {
    const node = nodes.find(n => n.id === id);
    emit({ nodes: nodes.map(n => n.id === id ? { ...n, ...patch } : n) }, { persist: false });
    const hostPatch = {};
    if (patch.status !== undefined) {
      hostPatch.status = patch.status;
    }
    if (patch.ip !== undefined) {
      hostPatch.ip = patch.ip;
    }
    if (patch.ips !== undefined) {
      hostPatch.ips = patch.ips;
    }
    if (patch.label !== undefined) {
      hostPatch.hostname = patch.label;
    }
    if (patch.os !== undefined) {
      hostPatch.os = patch.os;
    }
    if (patch.tags !== undefined) {
      hostPatch.tags = patch.tags;
    }
    if (patch.role !== undefined) {
      hostPatch.role = patch.role;
      hostPatch.is_attacker = patch.role === 'attacker';
    }
    if (patch.is_attacker !== undefined) {
      hostPatch.is_attacker = patch.is_attacker;
    }
    if (patch.type !== undefined) {
      const roleEntry = Object.entries(HOST_ROLES).find(([, meta]) => meta.nodeType === patch.type) || (patch.type === 'dc' ? ['domain_controller', HOST_ROLES.domain_controller] : null);
      if (roleEntry && patch.role === undefined) {
        hostPatch.role = roleEntry[0];
        hostPatch.is_attacker = roleEntry[0] === 'attacker';
      }
    }
    scheduleHostSync({ ...node, ...patch }, hostPatch);
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkNode(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [emit, markLocalOp, net.id, newLocalMutationId, nodes, projectId, scheduleHostSync]);
  const updateEdge = useCallback((id, patch) => {
    emit({ edges: edges.map(e => e.id === id ? { ...e, ...patch } : e) }, { persist: false });
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkLink(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [edges, emit, markLocalOp, net.id, newLocalMutationId, projectId]);
  const updateRegion = useCallback((id, patch) => {
    emit({ regions: regions.map(r => r.id === id ? { ...r, ...patch } : r) }, { persist: false });
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.updateNetworkRegion(projectId, id, net.id, { ...patch, client_mutation_id: lid }).catch(() => {});
  }, [emit, markLocalOp, net.id, newLocalMutationId, projectId, regions]);
  const deleteEdge = useCallback(async (id) => {
    emit({ edges: edges.filter(e => e.id !== id) }, { persist: false });
    await api.deleteNetworkLink(projectId, id, net.id).catch(() => {});
  }, [edges, emit, net.id, projectId]);

  const onNodeMouseDown = async (e, nid) => {
    e.stopPropagation();
    
    if (connecting) {
      await _handleConnectEdges({ connecting, selectedNodeIds, nid, edges, projectId, net, newLocalMutationId, markLocalOp, emit });
      setConnecting(null);
      return;
    }
    
    // If Shift/Ctrl/Meta is held, toggle selection without starting drag
    if (e.shiftKey || e.ctrlKey || e.metaKey) {
      setSelectedNodeIds(prev => prev.includes(nid) ? prev.filter(x => x !== nid) : [...prev, nid]);
      setSelectedRegionId(null);
      return;
    }
    
    // Otherwise, select this node and start dragging
    if (!selectedNodeIds.includes(nid)) {
      setSelectedNodeIds([nid]);
    }
    setSelectedRegionId(null);
    const node = nodes.find(n => n.id === nid);
    const pt = getSVGPt(e);
    pendingNodeDragRef.current = {
      nid,
      startClientX: e.clientX,
      startClientY: e.clientY,
      offsetX: pt.x - node.x,
      offsetY: pt.y - node.y,
    };
  };

  const onRegionMouseDown = (e, rid) => {
    // If Shift is held, allow drag-select to work - don't stop propagation
    if (e.shiftKey) {
      return;
    }
    
    e.stopPropagation();
    // Allow dragging with LKM only in region edit mode or when region is already selected
    if (!regionEditMode && selectedRegionId !== rid) {
      return;
    }
    const region = regions.find(r => r.id === rid);
    setSelectedRegionId(rid);
    setSelectedNodeIds([]);
    const pt = getSVGPt(e);
    dragOffset.current = { x: pt.x - region.x, y: pt.y - region.y };
    interactionStartRef.current = cloneNet(draftNetRef.current);
    setDraggingRegion(rid);
  };
  
  const onRegionContextMenu = (e, rid) => {
    e.preventDefault();
    e.stopPropagation();
    setSelectedRegionId(rid);
    setSelectedNodeIds([]);
    setRegionEditMode(true);
  };

  const onSVGMouseDown = (e) => {
    if (e.button === 2) return; // Ignore right click on canvas
    
    // If shift key is held, start drag-select instead of panning
    if (e.shiftKey) {
      const pt = getSVGPt(e);
      setSelectBox({ startX: pt.x, startY: pt.y, endX: pt.x, endY: pt.y });
      setEdgeMenu(null);
      setRegionEditMode(false);
      return;
    }
    
    setSelectedNodeIds([]);
    setSelectedRegionId(null);
    setEdgeMenu(null);
    setRegionEditMode(false);
    setDraggingCanvas({ startX: e.clientX - pan.x, startY: e.clientY - pan.y });
  };

  const onMouseMove = (e) => {
    if (e.buttons === 0 && _isInteractionActive(draggingNode, draggingRegion, resizingRegion, draggingCanvas, selectBox, pendingNodeDragRef)) {
      onMouseUp();
      return;
    }

    if (selectBox) {
      _handleSelectBoxMove(e, selectBox, getSVGPt, nodes, setSelectBox, setSelectedNodeIds);
    } else if (pendingNodeDragRef.current && !draggingNode) {
      _tryPromotePendingDrag(e, pendingNodeDragRef, dragOffset, cloneNet, draftNetRef, interactionStartRef, setDraggingNode);
    } else if (draggingNode) {
      _handleNodeDragMove(e, draggingNode, dragOffset, getSVGPt, { draftNetRef, selectedNodeSet, emit, syncDraggedNodePositions });
    } else if (draggingRegion) {
      _handleRegionDragMove(e, draggingRegion, dragOffset, getSVGPt, draftNetRef, emit);
    } else if (resizingRegion) {
      _handleRegionResizeMove(e, resizingRegion, getSVGPt, draftNetRef, emit);
    } else if (draggingCanvas) {
      _handleCanvasPanMove(e, draggingCanvas, panRef, canvasGroupRef, zoom);
    }
  };

  const onMouseUp = () => {
    if (draggingCanvas) {
      setPan(panRef.current);
    }
    if (draggingNode || draggingRegion || resizingRegion) {
      _finalizeDragInteraction(draggingNode, draggingRegion, resizingRegion, { interactionStartRef, draftNetRef, pushHistorySnapshot, syncDraggedNodePositions, selectedNodeSet, newLocalMutationId, markLocalOp, projectId, net, flushNetUpdate });
    }
    setDraggingNode(null);
    setDraggingRegion(null);
    setResizingRegion(null);
    setDraggingCanvas(null);
    setSelectBox(null);
    pendingNodeDragRef.current = null;
    if (pendingServerNetRef.current) {
      _applyPendingServerNet(pendingServerNetRef, draftNetRef, setDraftNet);
    }
  };

  useEffect(() => {
    const hasActiveInteraction = !!(draggingNode || draggingRegion || resizingRegion || draggingCanvas || selectBox);
    if (!hasActiveInteraction) {
      return undefined;
    }

    const handleGlobalRelease = () => onMouseUp();
    globalThis.addEventListener('mouseup', handleGlobalRelease);
    globalThis.addEventListener('blur', handleGlobalRelease);
    return () => {
      globalThis.removeEventListener('mouseup', handleGlobalRelease);
      globalThis.removeEventListener('blur', handleGlobalRelease);
    };
  }, [draggingCanvas, draggingNode, draggingRegion, resizingRegion, selectBox]);

  const onWheel = (e) => { e.preventDefault(); setZoom(z => Math.min(3, Math.max(0.3, z * (e.deltaY < 0 ? 1.1 : 0.91)))); };

  useEffect(() => {
    return () => {
      if (commitTimerRef.current) {
        clearTimeout(commitTimerRef.current);
        onUpdate(draftNetRef.current);
      }
      Object.values(hostSyncTimersRef.current).forEach(clearTimeout);
      hostSyncTimersRef.current = {};
      pendingHostPatchesRef.current = {};
      pendingHostNodesRef.current = {};
    };
  }, [onUpdate]);

  useEffect(() => {
    if (!import.meta.env.DEV) {
      return undefined;
    }
    globalThis.measureNetworkMapPerformance = () => ({
      renderCount: renderCountRef.current,
      nodeCount: nodes.length,
      edgeCount: edges.length,
      regionCount: regions.length,
      visibleNodeCount: visibleNodes.length,
      visibleEdgeCount: visibleEdges.length,
      selectedNodeCount: selectedNodeIds.length,
      zoom,
    });
    return () => {
      if (globalThis.measureNetworkMapPerformance) {
        delete globalThis.measureNetworkMapPerformance;
      }
    };
  }, [edges.length, nodes.length, regions.length, selectedNodeIds.length, visibleEdges.length, visibleNodes.length, zoom]);

  useEffect(() => {
    if (!showAttackAnalyzer || analysisCreds || analysisCredsLoading) {
      return;
    }
    setAnalysisCredsLoading(true);
    api.getCreds(projectId)
      .then(setAnalysisCreds)
      .finally(() => setAnalysisCredsLoading(false));
  }, [analysisCreds, analysisCredsLoading, projectId, showAttackAnalyzer]);

  const addNode = async () => {
    const ip = nodeDraft.ip.trim();
    const hostname = nodeDraft.hostname.trim();
    if (!ip && !hostname) {
      return;
    }
    let host = hosts.find(h => h.pid === projectId && ((ip && h.ip === ip) || (hostname && h.hostname?.toLowerCase() === hostname.toLowerCase())));
    if (host) {
      host = await onUpdateHost?.(host.id, { hostname: hostname || host.hostname, ip: ip || host.ip, os: nodeDraft.os, role: nodeDraft.role, is_attacker: nodeDraft.role === 'attacker', status: nodeDraft.role === 'attacker' ? 'attacker' : nodeDraft.status, domain: nodeDraft.domain }) || host;
    } else {
      host = await onCreateHost({ pid: projectId, ip: ip || `0.0.0.${20 + (nodes.length % 200)}`, hostname: hostname || 'new-host', os: nodeDraft.os, role: nodeDraft.role, is_attacker: nodeDraft.role === 'attacker', domain: nodeDraft.domain, status: nodeDraft.role === 'attacker' ? 'attacker' : nodeDraft.status, ports: [], services: [], tags: [], notes: '' });
    }
    const existingNode = nodes.find(n => (n.host_id && n.host_id === host.id) || n.ip === host.ip);
    if (existingNode) {
      updateNode(existingNode.id, { host_id: host.id, label: host.hostname || host.ip, ip: host.ip, ips: host.ips || [host.ip], type: guessNodeType(host), status: isAttackerHost(host) ? 'attacker' : host.status, ports: host.ports || [], notes: host.notes || '' });
      setSelectedNodeIds([existingNode.id]);
    } else {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      const result = await api.createNetworkNode(projectId, {
        network_id: net.id,
        host_id: host.id,
        x: (300 - pan.x) / zoom,
        y: (200 - pan.y) / zoom,
        label: host.hostname || host.ip,
        ip: host.ip,
        ips: host.ips || [host.ip],
        type: guessNodeType(host),
        status: isAttackerHost(host) ? 'attacker' : host.status,
        ports: host.ports || [],
        notes: host.notes || '',
        role: host.role,
        is_attacker: host.is_attacker,
        client_mutation_id: lid,
      });
      emit({ nodes: [...nodes, result.node] }, { persist: false });
      setSelectedNodeIds([result.node.id]);
    }
    setNodeDraft({ ip: '', hostname: '', os: 'Unknown', role: 'unknown', status: 'unknown', domain: '' });
    setShowCreateNode(false);
  };

  const addRegion = () => {
    const i = regions.length % REGION_FILL.length;
    const lid = newLocalMutationId();
    markLocalOp?.(lid);
    api.createNetworkRegion(projectId, {
      network_id: net.id,
      x: 80,
      y: 80,
      w: 320,
      h: 180,
      label: `Subnet ${regions.length + 1}`,
      note: '',
      fill: REGION_FILL[i],
      stroke: REGION_STROKE[i],
      client_mutation_id: lid,
    }).then((result) => {
      emit({ regions: [...regions, result.region] }, { persist: false });
      setSelectedRegionId(result.region.id);
      setSelectedNodeIds([]);
    }).catch(() => {});
  };

  const deleteSelected = () => {
    if (selectedRegionId) {
      emit({ regions: regions.filter(r => r.id !== selectedRegionId) }, { persist: false });
      api.deleteNetworkRegion(projectId, selectedRegionId, net.id).catch(() => {});
      setSelectedRegionId(null);
      return;
    }
    if (!selectedNodeIds.length) {
      return;
    }
    emit({ nodes: nodes.filter(n => !selectedNodeSet.has(n.id)), edges: edges.filter(e => !selectedNodeSet.has(e.from) && !selectedNodeSet.has(e.to)) }, { persist: false });
    Promise.all(selectedNodeIds.map(async (nodeId) => {
      await api.deleteNetworkNode(projectId, nodeId, net.id).catch(() => {});
    })).finally(() => setSelectedNodeIds([]));
  };

  const existingIps = useMemo(() => new Set(nodes.map(n => n.ip)), [nodes]);
  const unplaced = useMemo(() => hosts.filter(h => !existingIps.has(h.ip)), [existingIps, hosts]);
  const largeGraphMode = nodes.length >= 120 || edges.length >= 200;
  const simplifiedNodes = largeGraphMode && zoom < 0.85;
  const animateEdges = animateLinks && (!largeGraphMode || zoom >= 0.85);
  const addFromProject = (selectedIps) => {
    const toAdd = hosts.filter(h => selectedIps.has(h.ip));
    const cols = Math.ceil(Math.sqrt(toAdd.length + 1));
    Promise.all(toAdd.map(async (h, i) => {
      const lid = newLocalMutationId();
      markLocalOp?.(lid);
      const result = await api.createNetworkNode(projectId, {
        network_id: net.id,
        host_id: h.id,
        x: 120 + (i % cols) * 140,
        y: 120 + Math.floor(i / cols) * 140,
        label: h.hostname || h.ip,
        ip: h.ip,
        ips: h.ips || [],
        type: guessNodeType(h),
        status: isAttackerHost(h) ? 'attacker' : h.status || 'alive',
        ports: h.ports || [],
        notes: h.notes || '',
        role: h.role,
        is_attacker: h.is_attacker,
        client_mutation_id: lid,
      });
      return result.node;
    })).then((created) => {
      emit({ nodes: [...nodes, ...created.filter(Boolean)] }, { persist: false });
    }).finally(() => setShowAddFromProject(false));
    setShowAddFromProject(false);
  };


  const markerFor = (edge) => {
    const s = typeof edge === 'string' ? edge : (edge?.style || '');
    const t = typeof edge === 'string' ? '' : (edge?.type || '');
    if (s === 'exploit') {
      return 'url(#me)';
    }
    if (s === 'lateral' || t === 'lateral' || t === 'pivot') {
      return 'url(#ml)';
    }
    if (t === 'uplink') {
      return 'url(#morange)';
    }
    if (s === 'tunnel') {
      return 'url(#mt)';
    }
    if (t === 'domain_admin') {
      return 'url(#mred)';
    }
    if (t === 'domain_member' || t === 'auth_path' || t === 'trust') {
      return 'url(#mp)';
    }
    if (t === 'same_subnet' || t === 'lan' || t === 'routed') {
      return 'url(#mgray)';
    }
    if (t === 'internet_facing') {
      return 'url(#morange)';
    }
    return 'url(#mgreen)';
  };
  const canUndo = historyState.past.length > 0;
  const canRedo = historyState.future.length > 0;

  const undo = useCallback(() => {
    setHistoryState(state => {
      if (!state.past.length) {
        return state;
      }
      const previous = state.past[state.past.length - 1];
      const current = cloneNet(draftNetRef.current);
      queueMicrotask(() => applySnapshot(previous));
      return { past: state.past.slice(0, -1), future: [current, ...state.future] };
    });
  }, [applySnapshot, cloneNet]);

  const redo = useCallback(() => {
    setHistoryState(state => {
      if (!state.future.length) {
        return state;
      }
      const next = state.future[0];
      const current = cloneNet(draftNetRef.current);
      queueMicrotask(() => applySnapshot(next));
      return { past: [...state.past, current], future: state.future.slice(1) };
    });
  }, [applySnapshot, cloneNet]);

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <div style={{ padding: '7px 14px', borderBottom: '1px solid #1a1c22', background: '#0a0c10', display: 'flex', alignItems: 'center', gap: 7, flexShrink: 0 }}>
        <span style={{ fontSize: 10, color: '#505560', fontFamily: 'JetBrains Mono', flex: 1 }}>{nodes.length} nodes · {edges.length} edges · {regions.length} regions</span>
        <button onClick={() => setZoom(z => Math.min(3, z * 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomin" size={12} color="currentColor" /></button>
        <button onClick={() => setZoom(z => Math.max(0.3, z / 1.2))} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="zoomout" size={12} color="currentColor" /></button>
        <button onClick={() => { setZoom(1); setPan({ x: 40, y: 40 }); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#606570', cursor: 'pointer' }}><Icon name="reset" size={12} color="currentColor" /></button>
        <button onClick={undo} disabled={!canUndo} title="Undo (Ctrl/Cmd+Z)" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: canUndo ? '#9098a8' : '#404550', cursor: canUndo ? 'pointer' : 'default', opacity: canUndo ? 1 : 0.5, fontSize: 10, fontFamily: 'JetBrains Mono' }}>Undo</button>
        <button onClick={redo} disabled={!canRedo} title="Redo (Ctrl/Cmd+Shift+Z / Ctrl/Cmd+Y)" style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: canRedo ? '#9098a8' : '#404550', cursor: canRedo ? 'pointer' : 'default', opacity: canRedo ? 1 : 0.5, fontSize: 10, fontFamily: 'JetBrains Mono' }}>Redo</button>
        <span style={{ fontSize: 9, color: '#404550' }}>{Math.round(zoom * 100)}%</span>
        <div style={{ width: 1, height: 16, background: '#2a2d35' }} />
        {unplaced.length > 0 && <button onClick={() => setShowAddFromProject(v => !v)} style={{ background: 'none', border: `1px solid ${accent}66`, borderRadius: 4, padding: '4px 10px', color: accent, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>+ from project ({unplaced.length})</button>}
        <button onClick={() => setShowAttackAnalyzer(true)} style={{ background: 'none', border: '1px solid #cc223366', borderRadius: 4, padding: '4px 10px', color: '#cc2233', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 5 }}>⚡ Attack paths</button>
        <button onClick={addRegion} style={{ background: 'none', border: `1px solid ${accentGreen}66`, borderRadius: 4, padding: '4px 10px', color: accentGreen, cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Region</button>
        <button onClick={() => setShowCreateNode(v => !v)} style={{ background: accent, border: 'none', borderRadius: 4, padding: '4px 10px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Node</button>
        {selectedNodeIds.length > 0 && <><button onClick={() => setConnecting(selectedNodeIds[0])} title={selectedNodeIds.length > 1 ? `Create edges from ${selectedNodeIds.length} nodes` : 'Create edge'} style={{ background: connecting ? `${accentGreen}22` : 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: connecting ? accentGreen : '#606570', cursor: 'pointer' }}><Icon name="link" size={12} color="currentColor" />{selectedNodeIds.length > 1 && <span style={{ fontSize: 9, marginLeft: 4, fontFamily: 'JetBrains Mono' }}>×{selectedNodeIds.length}</span>}</button><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button></>}
        {selectedRegionId && regionEditMode && <><button onClick={deleteSelected} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 8px', color: '#cc2233', cursor: 'pointer' }}><Icon name="trash" size={12} color="currentColor" /></button><button onClick={() => { setRegionEditMode(false); setSelectedRegionId(null); }} style={{ background: 'none', border: '1px solid #2a2d35', borderRadius: 4, padding: '4px 10px', color: '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Done</button></>}
      </div>

      {largeGraphMode && (
        <div style={{ padding: '8px 14px', borderBottom: '1px solid #1a1c22', background: '#0b1016', color: '#6fc8f0', fontSize: 10, fontFamily: 'JetBrains Mono', flexShrink: 0 }}>
          Large graph mode enabled: labels and badges are simplified while zoomed out to keep idle CPU low.
        </div>
      )}

      {showAddFromProject && unplaced.length > 0 && <AddFromProjectPanel hosts={unplaced} accent={accent} onAdd={addFromProject} onClose={() => setShowAddFromProject(false)} />}
      {showCreateNode && <div style={{ background: '#0c0e13', borderBottom: '1px solid #2a2d35', padding: '10px 14px', display: 'flex', gap: 8, flexWrap: 'wrap', alignItems: 'flex-end' }}>
        <div style={{ width: 150 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>IP</div><input value={nodeDraft.ip} onChange={e => setNodeDraft(d => ({ ...d, ip: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <div style={{ width: 150 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Hostname</div><input value={nodeDraft.hostname} onChange={e => setNodeDraft(d => ({ ...d, hostname: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>OS</div><select value={nodeDraft.os} onChange={e => setNodeDraft(d => ({ ...d, os: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{['Unknown','Windows','Linux','macOS','Various'].map(v => <option key={v} value={v}>{v}</option>)}</select></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Role</div><select value={nodeDraft.role} onChange={e => setNodeDraft(d => ({ ...d, role: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{Object.entries(HOST_ROLES).map(([key, meta]) => <option key={key} value={key}>{meta.label}</option>)}</select></div>
        <div><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Status</div><select value={nodeDraft.status} onChange={e => setNodeDraft(d => ({ ...d, status: e.target.value }))} style={{ background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }}>{Object.keys(NODE_STATUS).map(v => <option key={v} value={v}>{NODE_STATUS[v].label}</option>)}</select></div>
        <div style={{ width: 160 }}><div style={{ fontSize: 9, color: '#404550', marginBottom: 4, textTransform: 'uppercase' }}>Domain</div><input value={nodeDraft.domain} onChange={e => setNodeDraft(d => ({ ...d, domain: e.target.value }))} style={{ width: '100%', background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 8px', color: '#c8cdd6', fontSize: 10, fontFamily: 'JetBrains Mono' }} /></div>
        <button onClick={addNode} style={{ background: accent, border: 'none', borderRadius: 4, padding: '6px 12px', color: '#fff', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Save node</button>
        <button onClick={() => setShowCreateNode(false)} style={{ background: 'transparent', border: '1px solid #2a2d35', borderRadius: 4, padding: '6px 10px', color: '#606570', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono' }}>Cancel</button>
      </div>}

        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <button type="button" aria-label="Network map canvas" tabIndex={0} style={{ flex: 1, position: 'relative', overflow: 'hidden', background: draftNet?.background || '#07080b', border: 'none', padding: 0, font: 'inherit', color: 'inherit', textAlign: 'left', display: 'block', width: '100%' }} onMouseMove={onMouseMove} onMouseUp={onMouseUp} onMouseLeave={onMouseUp} onContextMenu={e => e.preventDefault()} onKeyDown={e => { if (e.key === 'Tab') e.stopPropagation(); }} onKeyUp={() => {}}>
          <svg ref={svgRef} style={{ position: 'absolute', inset: 0, width: '100%', height: '100%' }} onMouseDown={onSVGMouseDown} onWheel={onWheel}>
            <style>{`.map-node .node-hov{opacity:0}.map-node:hover .node-hov{opacity:.5}.map-node-sel .node-hov{opacity:0!important}`}</style>
            <defs>
              <pattern id="sg" width="20" height="20" patternUnits="userSpaceOnUse"><path d="M 20 0 L 0 0 0 20" fill="none" stroke="#ffffff05" strokeWidth="1" /></pattern>
              <pattern id="lg" width="100" height="100" patternUnits="userSpaceOnUse"><path d="M 100 0 L 0 0 0 100" fill="none" stroke="#ffffff09" strokeWidth="1" /></pattern>
              {[['mgreen', '#39d353'], ['me', '#cc2233'], ['ml', '#e8cc42'], ['mt', '#5b8af5'], ['mp', '#8f7af5'], ['mgray', '#2a3548'], ['mred', '#e8574a'], ['morange', '#f09a3a']].map(([id, c]) => <marker key={id} id={id} markerWidth="8" markerHeight="8" refX="6" refY="3" orient="auto"><path d="M0,0 L0,6 L8,3 z" fill={c} /></marker>)}
            </defs>
            <g ref={canvasGroupRef} transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
              <rect x="-50000" y="-50000" width="100000" height="100000" fill="url(#sg)" style={{ pointerEvents: 'none' }} />
              <rect x="-50000" y="-50000" width="100000" height="100000" fill="url(#lg)" style={{ pointerEvents: 'none' }} />
              {regions.map(region => <g key={region.id} role="button" tabIndex={0} transform={`translate(${region.x},${region.y})`} onMouseDown={(e) => onRegionMouseDown(e, region.id)} onContextMenu={(e) => onRegionContextMenu(e, region.id)} style={{ cursor: regionEditMode && selectedRegionId === region.id ? 'move' : 'default' }}>
                <rect x="0" y="0" width={region.w} height={region.h} rx="12" fill={region.fill || '#5b8af522'} stroke={region.stroke || '#5b8af5'} strokeWidth={selectedRegionId === region.id ? 2.5 : 1.5} strokeDasharray={selectedRegionId === region.id ? '8 4' : undefined} />
                <text x="14" y="22" fontSize="12" fill={region.stroke || '#5b8af5'} fontFamily="Space Grotesk" fontWeight="700" style={{ pointerEvents: 'none' }}>{region.label}</text>
                {region.zone_type && <text x="14" y="36" fontSize="9" fill={region.stroke || '#5b8af5'} fontFamily="JetBrains Mono" fontWeight="600" style={{ pointerEvents: 'none', opacity: 0.8 }}>[{region.zone_type.toUpperCase()}]</text>}
                {region.note && <text x="14" y={region.zone_type ? 48 : 38} fontSize="9" fill="#c8cdd6" fontFamily="JetBrains Mono" style={{ pointerEvents: 'none' }}>{region.note}</text>}
                {region.via_host_id ? (() => {
                  const viaHost = projectHosts.find(h => h.id === region.via_host_id);
                  const viaLabel = `⇄ via ${viaHost?.hostname || viaHost?.ip || 'pivot'}`;
                  const yOff = (region.zone_type ? 48 : 38) + (region.note ? 13 : 0);
                  return <text x="14" y={yOff} fontSize="9" fill="#c07af0" fontFamily="JetBrains Mono" fontWeight="600" style={{ pointerEvents: 'none' }}>{viaLabel}</text>;
                })() : null}
                {selectedRegionId === region.id && regionEditMode && ['nw','ne','sw','se'].map(corner => {
                  const pos = {
                    nw: { x: 0, y: 0 },
                    ne: { x: region.w, y: 0 },
                    sw: { x: 0, y: region.h },
                    se: { x: region.w, y: region.h },
                  }[corner];
                  return <circle key={corner} cx={pos.x} cy={pos.y} r="5" fill={region.stroke || '#5b8af5'} stroke="#0e1016" strokeWidth="1.5" style={{ cursor: `${corner}-resize` }} onMouseDown={(e) => { e.stopPropagation(); interactionStartRef.current = cloneNet(draftNetRef.current); setResizingRegion({ id: region.id, corner }); }} />;
                })}
              </g>)}
              {visibleEdges.map(edge => {
                const fn = nodeById.get(edge.from); const tn = nodeById.get(edge.to); if (!fn || !tn) return null;
                const ep = edgeStyle(edge);
                const mx = (fn.x + tn.x) / 2;
                const my = (fn.y + tn.y) / 2;
                const edgeLabel = String(edge.label || '').trim();
                const _ACCESS_EDGE_TYPES = new Set(['ssh','winrm','smb_admin','local_admin','shell','c2_session','lateral','pivot','auth_path','uplink']);
                const isAccessEdge = _ACCESS_EDGE_TYPES.has(edge.type || '') || edge.source === 'scope_via';
                const edgeDimmed = attackPathSet
                  ? !attackPathSet.edges.has(edge.id)
                  : (accessOverlay && !isAccessEdge);
                return <g key={edge.id} style={{ opacity: edgeDimmed ? 0.06 : 1, transition: 'opacity .2s' }}><line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke={ep.stroke} strokeWidth={ep.sw} strokeDasharray={animateLinks && ep.dash !== 'none' ? ep.dash : undefined} markerEnd={markerFor(edge)} opacity=".9" style={animateEdges && ep.anim ? { animation: 'dash 1.5s linear infinite' } : undefined} />{edgeLabel && !simplifiedNodes && <><rect x={mx - edgeLabel.length * 3 - 4} y={my - 8} width={edgeLabel.length * 6 + 8} height={14} rx="3" fill="#0e1016" stroke={ep.stroke} strokeWidth="0.5" opacity=".95" /><text x={mx} y={my + 3} textAnchor="middle" fontSize="9" fill={ep.stroke} fontFamily="JetBrains Mono">{edgeLabel}</text></>}<line x1={fn.x} y1={fn.y} x2={tn.x} y2={tn.y} stroke="transparent" strokeWidth={14} style={{ cursor: 'default' }} onContextMenu={(e) => { e.preventDefault(); e.stopPropagation(); setEdgeMenu({ x: e.clientX, y: e.clientY, edgeId: edge.id }); }} /></g>;
              })}
              {visibleNodes.map(node => {
                const sc = NODE_STATUS[node.status]?.color || '#404550';
                const isSel = selectedNodeSet.has(node.id);
                const isDimmed = attackPathSet ? !attackPathSet.nodes.has(node.id) : false;
                let displayIps = [];
                if (node.ips?.length > 0) displayIps = node.ips;
                else if (node.ip) displayIps = [node.ip];
                const overlayEntry = showOverlay && overlayData ? (
                  overlayData.get(node.host_id) || overlayData.get(node.ip) || null
                ) : null;
                return <g key={node.id} className={`map-node${isSel ? ' map-node-sel' : ''}`} transform={`translate(${node.x - 20},${node.y - 20})`} onMouseDown={(e) => onNodeMouseDown(e, node.id)} style={{ '--sc': sc, cursor: 'pointer', userSelect: 'none', opacity: isDimmed ? 0.15 : 1, filter: isDimmed ? 'grayscale(0.7)' : undefined, transition: 'opacity .2s, filter .2s' }}>
                  {isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${accent}18`} stroke={accent} strokeWidth="1.5" />}
                  {overlayEntry && isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}33`} stroke={overlayEntry.color} strokeWidth="3" />}
                  {overlayEntry && !isSel && <rect x="-5" y="-5" width="50" height="50" rx="10" fill={`${overlayEntry.color}22`} stroke={overlayEntry.color} strokeWidth="2" strokeDasharray="4 2" opacity=".9" />}
                  <rect className="node-hov" x="-3" y="-3" width="46" height="46" rx="9" fill="#ffffff08" stroke="var(--sc)" strokeWidth="1" style={{ pointerEvents: 'none' }} />
                  <NodeShape type={node.type} status={node.status} size={40} selected={isSel} accent={accent} />
                  {overlayEntry && <circle cx="4" cy="4" r="5" fill={overlayEntry.color} opacity=".95" style={{ filter: `drop-shadow(0 0 4px ${overlayEntry.color})` }} />}
                  <circle cx="36" cy="4" r="4" fill={sc} opacity=".9" style={{ filter: `drop-shadow(0 0 3px ${sc})` }} />
                  {(() => {
                    const pivotInfo = node.host_id ? pivotByHostId.get(node.host_id) : null;
                    if (!pivotInfo || simplifiedNodes) {
                      return null;
                    }
                    const isSocks = pivotInfo.type === 'socks5' || pivotInfo.type === 'socks4';
                    let label;
                    if (isSocks) {
                      label = 'SOCKS';
                    }
                    else if (pivotInfo.type === 'route') {
                      label = 'ROUTE';
                    }
                    else {
                      label = 'PIVOT';
                    }
                    const pc = isSocks ? '#e8cc42' : '#f09a3a';
                    const w = label.length * 5.5 + 6;
                    return (
                      <g transform={`translate(${20 - w/2}, 41)`}>
                        <rect x="0" y="0" width={w} height="9" rx="2" fill={pc + '22'} stroke={pc + '88'} strokeWidth=".8" />
                        <text x={w/2} y="6.5" textAnchor="middle" fontSize="5.5" fill={pc} fontFamily="JetBrains Mono" fontWeight="700">{label}</text>
                      </g>
                    );
                  })()}
                  {(!simplifiedNodes || isSel) && <text x="20" y="53" textAnchor="middle" fontSize="10" fill={isSel ? '#f0f2f6' : '#9098a8'} fontFamily="JetBrains Mono" fontWeight={isSel ? 600 : 400}>{node.label}</text>}
                  {!simplifiedNodes && displayIps.map((ip, idx) => (
                    <text key={ip || `ip-${idx}`} x="20" y={64 + (idx * 9)} textAnchor="middle" fontSize="8" fill={sc} fontFamily="JetBrains Mono" opacity=".8">{ip}</text>
                  ))}
                  {!simplifiedNodes && (() => {
                    const roleBadges = roleBadgesByNodeId.get(node.id) || [];
                    const ipCount = displayIps.length;
                    let badgeY = 64 + ipCount * 9 + 4;
                    const roleElems = roleBadges.length ? renderRoleBadges(roleBadges, badgeY) : null;
                    if (roleBadges.length) {
                      badgeY += 13;
                    }
                    const ZONE_COLORS = { internal: '#5b8af5', dmz: '#f09a3a', external: '#cc2233', management: '#c07af0', scope_pivot: '#f09a3a' };
                    const zoneElem = node.zone_type && node.zone_type !== 'scope' ? (() => {
                      const zc = ZONE_COLORS[node.zone_type] || '#606570';
                      const zLabel = node.zone_type.toUpperCase().slice(0, 4);
                      return (
                        <g transform={`translate(${20 - 12},${badgeY})`}>
                          <rect x="0" y="0" width="24" height="10" rx="2.5" fill={zc + '22'} stroke={zc + '55'} strokeWidth=".8"/>
                          <text x="12" y="7.5" textAnchor="middle" fontSize="6" fill={zc} fontFamily="JetBrains Mono" fontWeight="700">{zLabel}</text>
                        </g>
                      );
                    })() : null;
                    // SB3: Tier-0/1/2 chip — top-right corner; Tier 2 is silent
                    const TIER_COLORS = { 0: '#e8574a', 1: '#f09a3a' };
                    const tierVal = (node.tier === 0 || node.tier === 1) ? node.tier : null;
                    const tierElem = tierVal === null ? null : (() => {
                      const tc = TIER_COLORS[tierVal];
                      return (
                        <g transform="translate(33,-2)">
                          <circle cx="0" cy="0" r="6" fill={tc + '33'} stroke={tc} strokeWidth="1"/>
                          <text x="0" y="2" textAnchor="middle" fontSize="6.5" fill={tc} fontFamily="JetBrains Mono" fontWeight="700">{`T${tierVal}`}</text>
                        </g>
                      );
                    })();
                    if (!roleElems && !zoneElem && !tierElem) {
                      return null;
                    }
                    return <>{roleElems}{zoneElem}{tierElem}</>;
                  })()}
                </g>;
              })}
              
              {/* Selection box visualization */}
              {selectBox && (() => {
                const minX = Math.min(selectBox.startX, selectBox.endX);
                const minY = Math.min(selectBox.startY, selectBox.endY);
                const width = Math.abs(selectBox.endX - selectBox.startX);
                const height = Math.abs(selectBox.endY - selectBox.startY);
                return <rect x={minX} y={minY} width={width} height={height} fill={`${accent}15`} stroke={accent} strokeWidth="1.5" strokeDasharray="4 4" />;
              })()}
            </g>
          </svg>
          {connecting && <div style={{ position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)', background: `${accentGreen}22`, border: `1px solid ${accentGreen}`, borderRadius: 6, padding: '8px 16px', zIndex: 200, backdropFilter: 'blur(4px)' }}>
            <div style={{ fontSize: 11, color: accentGreen, fontFamily: 'Space Grotesk', fontWeight: 600, textAlign: 'center' }}>
              Edge creation mode {selectedNodeIds.length > 1 && `(from ${selectedNodeIds.length} nodes)`}
            </div>
            <div style={{ fontSize: 9, color: '#9098a8', fontFamily: 'JetBrains Mono', marginTop: 4, textAlign: 'center' }}>
              Click the target node or press ESC to cancel
            </div>
          </div>}
          {edgeMenu && (() => {
            const _menuEdge = edges.find(e => e.id === edgeMenu.edgeId);
            const _isVerified = !!_menuEdge?.verified;
            const _menuBtnBase = { background: 'transparent', border: 'none', cursor: 'pointer', fontSize: 10, fontFamily: 'JetBrains Mono', display: 'flex', alignItems: 'center', gap: 6, padding: '4px 8px', width: '100%', textAlign: 'left' };
            return (
              <div style={{ position: 'fixed', top: edgeMenu.y, left: edgeMenu.x, zIndex: 300, background: '#0e1016', border: '1px solid #2a2d35', borderRadius: 6, padding: 6, boxShadow: '0 8px 24px #00000088', minWidth: 140 }}>
                <button
                  onClick={() => { updateEdge(edgeMenu.edgeId, { verified: !_isVerified, manual_override: true }); setEdgeMenu(null); }}
                  style={{ ..._menuBtnBase, color: _isVerified ? '#808590' : '#39d353' }}
                  title={_isVerified ? 'Mark this edge as inferred (auto)' : 'Promote this edge to verified — survives Smart Build rebuilds'}
                >
                  <Icon name={_isVerified ? 'eyeOff' : 'check'} size={11} color={_isVerified ? '#808590' : '#39d353'} />
                  {_isVerified ? 'Unverify edge' : 'Verify edge'}
                </button>
                <div style={{ height: 1, background: '#2a2d35', margin: '4px 0' }} />
                <button
                  onClick={() => { deleteEdge(edgeMenu.edgeId); setEdgeMenu(null); }}
                  style={{ ..._menuBtnBase, color: '#cc2233' }}
                >
                  <Icon name="trash" size={11} color="#cc2233" /> Delete edge
                </button>
              </div>
            );
          })()}
          <div style={{ position: 'absolute', bottom: 12, left: 12, background: '#0c0e13cc', border: '1px solid #1e2029', borderRadius: 6, padding: '8px 12px', backdropFilter: 'blur(4px)', display: 'flex', gap: 16 }}>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Status</div>
              {Object.entries(NODE_STATUS).map(([k, v]) => <div key={k} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}><span style={{ width: 6, height: 6, borderRadius: '50%', background: v.color, display: 'inline-block' }} /><span style={{ fontSize: 9, color: '#606570' }}>{v.label}</span></div>)}
            </div>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Edges</div>
              {[['Access (verified)', '#39d353'], ['Access (inferred)', '#39d35399'], ['Entry uplink', '#f09a3a'], ['Domain admin', '#e8574a'], ['Exploit', '#cc2233'], ['Lateral/Pivot', '#e8cc42'], ['Tunnel', '#5b8af5'], ['Domain', '#8f7af5'], ['Subnet', '#3a4a5a']].map(([l, c]) => <div key={l} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}><span style={{ width: 14, height: 1.5, background: c, display: 'inline-block' }} /><span style={{ fontSize: 9, color: '#606570' }}>{l}</span></div>)}
            </div>
            <div>
              <div title="P5: derived transport on access edges" style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Transport</div>
              {Object.entries(TRANSPORT_COLORS).map(([t, c]) => <div key={t} style={{ display: 'flex', alignItems: 'center', gap: 5, marginBottom: 3 }}><span style={{ width: 12, height: 12, borderRadius: 2, background: c + '18', border: `1px solid ${c}55`, color: c, fontSize: 7, fontFamily: 'JetBrains Mono', textAlign: 'center', lineHeight: '12px', textTransform: 'uppercase' }}>{t[0]}</span><span style={{ fontSize: 9, color: '#606570', textTransform: 'uppercase', letterSpacing: '0.05em' }}>{t}</span></div>)}
            </div>
            <div>
              <div style={{ fontSize: 8, color: '#404550', letterSpacing: '0.1em', textTransform: 'uppercase', marginBottom: 5 }}>Keyboard shortcuts</div>
              <div style={{ fontSize: 9, color: '#606570', marginBottom: 3 }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Shift</kbd> + drag — select area</div>
              <div style={{ fontSize: 9, color: '#606570', marginBottom: 3 }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Ctrl+A</kbd> — select all</div>
              <div style={{ fontSize: 9, color: '#606570' }}><kbd style={{ background: '#1a1c22', padding: '1px 4px', borderRadius: 2, fontFamily: 'JetBrains Mono' }}>Esc</kbd> — deselect</div>
            </div>
          </div>
        </button>

        {showAttackAnalyzer && analysisCredsLoading && (
          <div style={{ width: 320, background: '#0c0e13', borderLeft: '1px solid #1e2029', padding: 14, color: '#404550', fontSize: 10, fontFamily: 'JetBrains Mono' }}>
            Loading attack path data…
          </div>
        )}
        {showAttackAnalyzer && analysisCreds && (
          <AttackVectorAnalyzer
            projectId={projectId}
            hosts={hosts}
            creds={analysisCreds}
            nodes={nodes}
            existingEdges={edges}
            accent={accent}
            onApply={async (newEdges) => {
              const created = await Promise.all(newEdges.map(async (edge) => {
                const lid = newLocalMutationId();
                markLocalOp?.(lid);
                const result = await api.createNetworkLink(projectId, {
                  network_id: net.id,
                  from_node_id: edge.from,
                  to_node_id: edge.to,
                  style: edge.style || 'normal',
                  label: edge.label || '',
                  source: edge.source || 'manual',
                  type: edge.type,
                  confidence: edge.confidence,
                  client_mutation_id: lid,
                });
                return result.link;
              })).catch(() => []);
              if (created.length) emit({ edges: [...edges, ...created] }, { persist: false });
            }}
            onClose={() => setShowAttackAnalyzer(false)}
          />
        )}
        <NetworkInspector
          projectId={projectId}
          accent={accent}
          selectedNode={selectedNode}
          selectedRegion={selectedRegion}
          hostObj={hostObj}
          edges={edges}
          nodeById={nodeById}
          updateNode={updateNode}
          updateEdge={updateEdge}
          updateRegion={updateRegion}
          deleteEdge={deleteEdge}
          onClose={() => { setSelectedNodeIds([]); setSelectedRegionId(null); }}
          onAddActivity={onAddActivity}
          onUpdateActivity={onUpdateActivity}
          onDeleteActivity={onDeleteActivity}
          pivots={pivots}
          projectHosts={projectHosts}
          onDeletePivot={onDeletePivot}
          onUpdatePivot={onUpdatePivot}
          onAddPivotForHost={onAddPivotForHost}
        />
      </div>
    </div>
  );
}

NetworkCanvas.propTypes = {
  projectId: PropTypes.any,
  net: PropTypes.object,
  onUpdate: PropTypes.func,
  onCreateHost: PropTypes.func,
  onUpdateHost: PropTypes.func,
  onSyncHostByIp: PropTypes.func,
  accent: PropTypes.string,
  accentGreen: PropTypes.string,
  hosts: PropTypes.array,
  onAddActivity: PropTypes.func,
  onUpdateActivity: PropTypes.func,
  onDeleteActivity: PropTypes.func,
  markLocalOp: PropTypes.func,
  animateLinks: PropTypes.bool,
  overlayData: PropTypes.object,
  accessOverlay: PropTypes.bool,
  overlayMode: PropTypes.string,
  pivots: PropTypes.array,
  projectHosts: PropTypes.array,
  onDeletePivot: PropTypes.func,
  onUpdatePivot: PropTypes.func,
  onAddPivotForHost: PropTypes.func,
};
