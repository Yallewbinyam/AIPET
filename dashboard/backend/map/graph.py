"""
AIPET Map — Network Graph Calculator
Builds a network attack path graph from scan findings and device tags.

Takes findings and device tags as input and returns:
- Network nodes (devices)
- Network edges (connections)
- Attack paths (entry point → critical asset)
- Recommendations (which fix breaks the most paths)

Usage:
    from dashboard.backend.map.graph import build_graph
    result = build_graph(findings, device_tags)
"""


# ── Severity Configuration ─────────────────────────────────────────────────
SEVERITY_RANK = {
    "Critical": 4,
    "High":     3,
    "Medium":   2,
    "Low":      1,
    "Info":     0,
}

SEVERITY_COLORS = {
    "Critical": "#ef4444",
    "High":     "#f97316",
    "Medium":   "#eab308",
    "Low":      "#22c55e",
    "Info":     "#6b7280",
    "None":     "#3b82f6",
}

# ── Critical Asset Functions ───────────────────────────────────────────────
# Devices tagged with these functions are considered critical assets
CRITICAL_ASSET_FUNCTIONS = [
    "Patient Records / Medical",
    "Financial / Payment",
    "Customer Data",
    "Research / IP",
    "HR / Employee Data",
]

# ── Entry Point Severities ─────────────────────────────────────────────────
# Devices with these severities are considered potential entry points
ENTRY_POINT_SEVERITIES = ["Critical", "High"]


def get_subnet(ip):
    """
    Extracts the /24 subnet from an IP address.
    192.168.1.100 → 192.168.1
    Used to determine which devices are on the same network segment.
    """
    try:
        parts = ip.strip().split(".")
        if len(parts) >= 3:
            return ".".join(parts[:3])
    except Exception:
        pass
    return None


def calculate_risk_score(findings_for_device):
    """
    Calculates a 0-100 risk score for a device based on its findings.
    Critical findings contribute most, Low findings least.
    """
    if not findings_for_device:
        return 0

    weights = {"Critical": 25, "High": 15, "Medium": 8, "Low": 3, "Info": 1}
    total   = sum(weights.get(f.get("severity", "Info"), 1) for f in findings_for_device)
    return min(total, 100)


def build_graph(findings, device_tags):
    """
    Builds a complete network attack graph from findings and device tags.

    Args:
        findings (list): List of finding dicts from the database
            Each finding: {id, attack, severity, target, fix_status, module}
        device_tags (dict): Mapping of device IP to business function
            e.g. {"192.168.1.1": "Infrastructure / Network"}

    Returns:
        dict: {
            "nodes": [...],
            "edges": [...],
            "attack_paths": [...],
            "recommendations": [...],
            "stats": {...}
        }
    """
    if not findings:
        return {
            "nodes":           [],
            "edges":           [],
            "attack_paths":    [],
            "recommendations": [],
            "stats": {
                "total_devices":    0,
                "entry_points":     0,
                "critical_assets":  0,
                "attack_paths":     0,
            }
        }

    # ── Step 1: Group findings by device ──────────────────────────────────
    devices = {}
    for f in findings:
        target = f.get("target", "").strip()
        if not target:
            continue
        if target not in devices:
            devices[target] = []
        devices[target].append(f)

    # ── Step 2: Build nodes ───────────────────────────────────────────────
    nodes = []
    for ip, device_findings in devices.items():
        # Find worst severity on this device
        worst_severity = "None"
        for f in device_findings:
            sev = f.get("severity", "Info")
            if SEVERITY_RANK.get(sev, 0) > SEVERITY_RANK.get(worst_severity, -1):
                worst_severity = sev

        device_fn   = device_tags.get(ip, "Unknown")
        is_critical = device_fn in CRITICAL_ASSET_FUNCTIONS
        is_entry    = worst_severity in ENTRY_POINT_SEVERITIES
        risk_score  = calculate_risk_score(device_findings)

        # Count fixed vs open findings
        open_count  = sum(1 for f in device_findings if f.get("fix_status") == "open")
        fixed_count = sum(1 for f in device_findings if f.get("fix_status") == "fixed")

        nodes.append({
            "id":            ip,
            "label":         ip,
            "severity":      worst_severity,
            "color":         SEVERITY_COLORS.get(worst_severity, SEVERITY_COLORS["None"]),
            "findings_count": len(device_findings),
            "findings":      device_findings,
            "device_function": device_fn,
            "is_entry":      is_entry,
            "is_critical":   is_critical,
            "risk_score":    risk_score,
            "open_findings": open_count,
            "fixed_findings": fixed_count,
            "subnet":        get_subnet(ip),
        })

    # ── Step 3: Build edges ───────────────────────────────────────────────
    # Connect devices on the same subnet
    edges = []
    edge_set = set()

    for i, node_a in enumerate(nodes):
        for j, node_b in enumerate(nodes):
            if i >= j:
                continue
            subnet_a = node_a.get("subnet")
            subnet_b = node_b.get("subnet")
            if subnet_a and subnet_b and subnet_a == subnet_b:
                edge_key = tuple(sorted([node_a["id"], node_b["id"]]))
                if edge_key not in edge_set:
                    edge_set.add(edge_key)
                    edges.append({
                        "source": node_a["id"],
                        "target": node_b["id"],
                        "type":   "network",
                    })

    # ── Step 4: Find attack paths ─────────────────────────────────────────
    entry_nodes    = [n for n in nodes if n["is_entry"]]
    critical_nodes = [n for n in nodes if n["is_critical"]]

    # Build adjacency map for path finding
    adjacency = {n["id"]: set() for n in nodes}
    for edge in edges:
        adjacency[edge["source"]].add(edge["target"])
        adjacency[edge["target"]].add(edge["source"])

    attack_paths = []

    for entry in entry_nodes:
        for critical in critical_nodes:
            if entry["id"] == critical["id"]:
                continue

            # BFS to find shortest path
            path = bfs_shortest_path(adjacency, entry["id"], critical["id"])
            if path:
                path_nodes = [n for n in nodes if n["id"] in path]
                path_severity = max(
                    (SEVERITY_RANK.get(n["severity"], 0) for n in path_nodes),
                    default=0
                )
                attack_paths.append({
                    "path":           path,
                    "entry":          entry["id"],
                    "target":         critical["id"],
                    "target_function": critical["device_function"],
                    "length":         len(path),
                    "severity":       path_severity,
                    "description":    f"Attack path: {entry['id']} → {critical['id']} ({critical['device_function']})"
                })

    # If no tagged critical assets, show paths between entry points
    if not attack_paths and len(entry_nodes) > 1:
        for i, entry_a in enumerate(entry_nodes):
            for entry_b in entry_nodes[i+1:]:
                path = bfs_shortest_path(adjacency, entry_a["id"], entry_b["id"])
                if path:
                    attack_paths.append({
                        "path":           path,
                        "entry":          entry_a["id"],
                        "target":         entry_b["id"],
                        "target_function": entry_b["device_function"],
                        "length":         len(path),
                        "severity":       3,
                        "description":    f"Lateral movement: {entry_a['id']} → {entry_b['id']}"
                    })

    # Sort paths by severity descending
    attack_paths.sort(key=lambda p: p["severity"], reverse=True)

    # ── Step 5: Generate recommendations ─────────────────────────────────
    recommendations = generate_recommendations(nodes, attack_paths, edges)

    # ── Step 6: Build stats ───────────────────────────────────────────────
    stats = {
        "total_devices":   len(nodes),
        "entry_points":    len(entry_nodes),
        "critical_assets": len(critical_nodes),
        "attack_paths":    len(attack_paths),
        "total_findings":  len(findings),
    }

    return {
        "nodes":           nodes,
        "edges":           edges,
        "attack_paths":    attack_paths,
        "recommendations": recommendations,
        "stats":           stats,
    }


def bfs_shortest_path(adjacency, start, end):
    """
    Finds the shortest path between two nodes using BFS.
    Returns a list of node IDs, or None if no path exists.
    """
    if start == end:
        return [start]

    visited = {start}
    queue   = [[start]]

    while queue:
        path = queue.pop(0)
        node = path[-1]

        for neighbour in adjacency.get(node, set()):
            if neighbour == end:
                return path + [neighbour]
            if neighbour not in visited:
                visited.add(neighbour)
                queue.append(path + [neighbour])

    return None


def generate_recommendations(nodes, attack_paths, edges):
    """
    Generates prioritised fix recommendations based on attack paths.

    Finds which devices appear on the most attack paths — fixing
    those devices breaks the most attack chains simultaneously.
    """
    if not attack_paths:
        # No attack paths — recommend fixing worst findings
        critical_nodes = [n for n in nodes if n["severity"] == "Critical"]
        recs = []
        for node in critical_nodes[:3]:
            worst_finding = None
            worst_rank    = -1
            for f in node["findings"]:
                rank = SEVERITY_RANK.get(f.get("severity", "Info"), 0)
                if rank > worst_rank:
                    worst_rank    = rank
                    worst_finding = f
            if worst_finding:
                recs.append({
                    "device":      node["id"],
                    "finding":     worst_finding.get("attack", "Unknown"),
                    "severity":    worst_finding.get("severity", "Unknown"),
                    "paths_broken": 0,
                    "message":     f"Fix {worst_finding.get('attack')} on {node['id']} to eliminate Critical risk"
                })
        return recs

    # Count how many paths each device appears on
    path_count = {}
    for path_data in attack_paths:
        for node_id in path_data["path"]:
            path_count[node_id] = path_count.get(node_id, 0) + 1

    # Sort by path count descending
    sorted_nodes = sorted(path_count.items(), key=lambda x: x[1], reverse=True)

    recommendations = []
    node_map = {n["id"]: n for n in nodes}

    for node_id, count in sorted_nodes[:3]:
        node = node_map.get(node_id)
        if not node:
            continue

        # Find the worst open finding on this device
        worst_finding = None
        worst_rank    = -1
        for f in node.get("findings", []):
            if f.get("fix_status") == "open":
                rank = SEVERITY_RANK.get(f.get("severity", "Info"), 0)
                if rank > worst_rank:
                    worst_rank    = rank
                    worst_finding = f

        if worst_finding:
            recommendations.append({
                "device":       node_id,
                "finding":      worst_finding.get("attack", "Unknown"),
                "severity":     worst_finding.get("severity", "Unknown"),
                "paths_broken": count,
                "message":      f"Fix {worst_finding.get('attack')} on {node_id} to disrupt {count} attack path{'s' if count > 1 else ''}"
            })

    return recommendations