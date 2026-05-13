export function applySyncEvent(msg, ctx) {
  const {
    localOps,
    setNotes,
    setHosts,
    setCreds,
    setNetworks,
    setFindings,
    setObjectives,
    setAttackPaths,
    setAttackSteps,
    setLoots,
    setScopes,
    setHostActivities,
    setJobs,
    setProjects,
    updateOneNetwork,
  } = ctx;

  const { entity, action, data } = msg;

  if (data?._lid && localOps.current.has(data._lid)) {
    localOps.current.delete(data._lid);
    return;
  }

  if (entity === 'note') {
    if (action === 'create') setNotes(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
    if (action === 'update') setNotes(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setNotes(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'host') {
    if (action === 'create') setHosts(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setHosts(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'upsert') setHosts(prev => prev.some(x => x.id === data.id) ? prev.map(x => x.id === data.id ? data : x) : [...prev, data]);
    if (action === 'delete') setHosts(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'cred') {
    if (action === 'create') setCreds(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setCreds(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setCreds(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'network') {
    if (action === 'create') setNetworks(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setNetworks(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setNetworks(prev => prev.filter(x => x.id !== data.id));
    if (action === 'node_created') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        nodes: net.nodes?.some(node => node.id === data.node.id) ? net.nodes : [...(net.nodes || []), data.node],
      }));
    }
    if (action === 'node_updated') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        nodes: (net.nodes || []).map(node => {
          if (node.id !== data.node.id) return node;
          if ((node.version || 0) > (data.node.version || 0)) return node;
          return { ...node, ...data.node };
        }),
      }));
    }
    if (action === 'node_position_updated') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        nodes: (net.nodes || []).map(node => {
          if (node.id !== data.node_id) return node;
          if ((node.version || 0) > (data.version || 0)) return node;
          return {
            ...node,
            x: data.position.x,
            y: data.position.y,
            manually_positioned: data.manually_positioned,
            auto_positioned: !data.manually_positioned,
            updated_at: data.updated_at,
            version: data.version,
          };
        }),
      }));
    }
    if (action === 'node_deleted') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        nodes: (net.nodes || []).filter(node => node.id !== data.node_id),
        edges: (net.edges || []).filter(edge => edge.from !== data.node_id && edge.to !== data.node_id && !(data.deleted_edge_ids || []).includes(edge.id)),
      }));
    }
    if (action === 'link_created') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        edges: net.edges?.some(edge => edge.id === data.link.id) ? net.edges : [...(net.edges || []), data.link],
      }));
    }
    if (action === 'link_updated') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        edges: (net.edges || []).map(edge => {
          if (edge.id !== data.link.id) return edge;
          if ((edge.version || 0) > (data.link.version || 0)) return edge;
          return { ...edge, ...data.link };
        }),
      }));
    }
    if (action === 'link_deleted') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        edges: (net.edges || []).filter(edge => edge.id !== data.link_id),
      }));
    }
    if (action === 'region_created') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        regions: net.regions?.some(region => region.id === data.region.id) ? net.regions : [...(net.regions || []), data.region],
      }));
    }
    if (action === 'region_updated') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        regions: (net.regions || []).map(region => {
          if (region.id !== data.region.id) return region;
          if ((region.version || 0) > (data.region.version || 0)) return region;
          return { ...region, ...data.region };
        }),
      }));
    }
    if (action === 'region_deleted') {
      updateOneNetwork(data.network_id, net => ({
        ...net,
        regions: (net.regions || []).filter(region => region.id !== data.region_id),
      }));
    }
    if (action === 'layout_applied' || action === 'topology_rebuilt') {
      if (data.network) {
        setNetworks(prev => prev.map(net => {
          if (net.id !== data.network.id) return net;
          const _RANK = { unknown: 0, alive: 1, up: 2, scanned: 3, access: 4, owned: 5, pwned: 5, attacker: 6 };
          const statusById = new Map((net.nodes || []).map(n => [n.id, n.status]));
          const statusByHostId = new Map((net.nodes || []).map(n => n.host_id ? [n.host_id, n.status] : null).filter(Boolean));
          const nodes = (data.network.nodes || []).map(n => {
            const cur = statusById.get(n.id) ?? statusByHostId.get(n.host_id);
            const inc = n.status;
            const status = cur && (_RANK[cur] ?? 0) >= (_RANK[inc] ?? 0) ? cur : inc;
            return { ...n, status };
          });
          return { ...data.network, nodes };
        }));
      }
    }
    if (action === 'layout_reset') {
      if (data.network) setNetworks(prev => prev.map(net => net.id === data.network.id ? data.network : net));
    }
  }
  if (entity === 'finding') {
    if (action === 'create') setFindings(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setFindings(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setFindings(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'objective') {
    if (action === 'create') setObjectives(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setObjectives(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setObjectives(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'attack_path') {
    if (action === 'create') setAttackPaths(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setAttackPaths(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setAttackPaths(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'attack_step') {
    if (action === 'create') setAttackSteps(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setAttackSteps(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setAttackSteps(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'loot') {
    if (action === 'create') setLoots(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
    if (action === 'update') setLoots(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setLoots(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'scope') {
    if (action === 'create') setScopes(prev => prev.some(x => x.id === data.id) ? prev : [...prev, data]);
    if (action === 'update') setScopes(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setScopes(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'host_activity') {
    if (action === 'create') setHostActivities(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
    if (action === 'update') setHostActivities(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setHostActivities(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'job') {
    if (action === 'create') setJobs(prev => prev.some(x => x.id === data.id) ? prev : [data, ...prev]);
    if (action === 'update') setJobs(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') setJobs(prev => prev.filter(x => x.id !== data.id));
  }
  if (entity === 'project') {
    if (action === 'update') setProjects(prev => prev.map(x => x.id === data.id ? data : x));
    if (action === 'delete') {
      setProjects(prev => prev.filter(x => x.id !== data.id));
      setNotes(prev => prev.filter(x => x.pid !== data.id));
      setHosts(prev => prev.filter(x => x.pid !== data.id));
      setCreds(prev => prev.filter(x => x.pid !== data.id));
      setNetworks(prev => prev.filter(x => x.pid !== data.id));
      setHostActivities(prev => prev.filter(x => x.pid !== data.id));
    }
  }
  if (entity === 'playbook_run') {
    window.dispatchEvent(new CustomEvent('rt:playbook_run', { detail: { action, data } }));
  }
}
