import numpy as np

FEATURE_ORDER = [
    "packet_rate",
    "byte_rate",
    "unique_dst_ports",
    "unique_dst_ips",
    "syn_ratio",
    "rst_ratio",
    "failed_auth_rate",
    "open_port_count",
    "cve_count",
    "outbound_ratio",
    "night_activity",
    "protocol_entropy",
]


def to_vector(sample: dict) -> np.ndarray:
    return np.array(
        [float(sample.get(f, 0.0)) for f in FEATURE_ORDER],
        dtype=np.float64,
    )
