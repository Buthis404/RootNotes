from .routes import router
from ._infer import infer_links, infer_links_smart, TopologyLinkDiff
from ._auto_build import _run_auto_build, topology_auto_build
from ._layout import compute_layout
from ._smart_build import topology_smart_build, SmartBuildRequest
from .routes import (
    TopologyOptions, TopologyHostDiff, TopologyPreview,
    ApplyRequest, RebuildLayoutRequest,
    get_topology_sources, get_topology, topology_preview,
    topology_apply, topology_rebuild_layout,
)
from .routes import (
    _require_topology_module_enabled, require_topo_read,
    require_topo_preview, require_topo_apply,
    _node_ref, _edge_ref,
    _parse_nmap_ports, _parse_nmap_hostname, _parse_nmap_os,
    _parse_nmap_host_el, parse_nmap_xml,
)
from ._edge_meta import _edge_action_tags, _decay_confidence, _score_pivot_candidate, _find_pivot_host
from ._lateral import topology_lateral_paths

__all__ = ["router"]
