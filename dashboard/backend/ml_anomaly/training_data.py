import numpy as np
from dashboard.backend.ml_anomaly.features import FEATURE_ORDER


def generate_synthetic(n_normal=5000, n_anomalous=250, seed=42):
    """
    Labeled synthetic IoT telemetry dataset for bootstrap training.
    Normal: low traffic, few ports, daytime bias, outbound-heavy.
    Anomalous: port-scan, C2-beacon, and exfiltration patterns.
    Returns (X, y) numpy arrays — y=0 normal, y=1 anomalous.
    """
    rng = np.random.RandomState(seed)
    f = {name: i for i, name in enumerate(FEATURE_ORDER)}

    # --- Normal traffic ---
    N = n_normal
    X_normal = np.zeros((N, len(FEATURE_ORDER)))
    X_normal[:, f["packet_rate"]]      = rng.normal(50,   15,   N).clip(1, 200)
    X_normal[:, f["byte_rate"]]        = rng.normal(5000, 1500, N).clip(100, 20000)
    X_normal[:, f["unique_dst_ports"]] = rng.randint(1, 5, N).astype(float)
    X_normal[:, f["unique_dst_ips"]]   = rng.randint(1, 8, N).astype(float)
    X_normal[:, f["syn_ratio"]]        = rng.beta(2,  10, N)
    X_normal[:, f["rst_ratio"]]        = rng.beta(1,  20, N)
    X_normal[:, f["failed_auth_rate"]] = rng.beta(1,  30, N)
    X_normal[:, f["open_port_count"]]  = rng.randint(1, 4, N).astype(float)
    X_normal[:, f["cve_count"]]        = rng.randint(0, 3, N).astype(float)
    X_normal[:, f["outbound_ratio"]]   = rng.beta(8,  2,  N)
    X_normal[:, f["night_activity"]]   = rng.beta(1,  5,  N)
    X_normal[:, f["protocol_entropy"]] = rng.normal(1.2, 0.3, N).clip(0, 3)

    # --- Port-scan pattern ---
    n_ps = n_anomalous // 3
    X_ps = np.zeros((n_ps, len(FEATURE_ORDER)))
    X_ps[:, f["packet_rate"]]      = rng.normal(800, 150, n_ps).clip(400, 2000)
    X_ps[:, f["byte_rate"]]        = rng.normal(3000, 800, n_ps).clip(500, 10000)
    X_ps[:, f["unique_dst_ports"]] = rng.randint(50, 500, n_ps).astype(float)
    X_ps[:, f["unique_dst_ips"]]   = rng.randint(10, 100, n_ps).astype(float)
    X_ps[:, f["syn_ratio"]]        = rng.beta(15, 2, n_ps).clip(0, 1)
    X_ps[:, f["rst_ratio"]]        = rng.beta(10, 2, n_ps).clip(0, 1)
    X_ps[:, f["failed_auth_rate"]] = rng.beta(5,  2, n_ps).clip(0, 1)
    X_ps[:, f["open_port_count"]]  = rng.randint(20, 200, n_ps).astype(float)
    X_ps[:, f["cve_count"]]        = rng.randint(0,  5,   n_ps).astype(float)
    X_ps[:, f["outbound_ratio"]]   = rng.beta(5,  5, n_ps)
    X_ps[:, f["night_activity"]]   = rng.beta(5,  2, n_ps)
    X_ps[:, f["protocol_entropy"]] = rng.normal(2.5, 0.3, n_ps).clip(0, 3)

    # --- C2 beacon pattern ---
    n_c2 = n_anomalous // 3
    X_c2 = np.zeros((n_c2, len(FEATURE_ORDER)))
    X_c2[:, f["packet_rate"]]      = rng.normal(30,  5,   n_c2).clip(5, 80)
    X_c2[:, f["byte_rate"]]        = rng.normal(800, 100, n_c2).clip(200, 2000)
    X_c2[:, f["unique_dst_ports"]] = rng.randint(1, 3, n_c2).astype(float)
    X_c2[:, f["unique_dst_ips"]]   = rng.randint(1, 3, n_c2).astype(float)
    X_c2[:, f["syn_ratio"]]        = rng.beta(2, 8, n_c2)
    X_c2[:, f["rst_ratio"]]        = rng.beta(1, 15, n_c2)
    X_c2[:, f["failed_auth_rate"]] = rng.beta(1, 10, n_c2)
    X_c2[:, f["open_port_count"]]  = rng.randint(1, 3, n_c2).astype(float)
    X_c2[:, f["cve_count"]]        = rng.randint(2, 8, n_c2).astype(float)
    X_c2[:, f["outbound_ratio"]]   = rng.beta(15, 1, n_c2).clip(0, 1)
    X_c2[:, f["night_activity"]]   = rng.beta(8,  2, n_c2)
    X_c2[:, f["protocol_entropy"]] = rng.normal(0.3, 0.1, n_c2).clip(0, 1)

    # --- Exfiltration pattern ---
    n_ex = n_anomalous - 2 * (n_anomalous // 3)
    X_ex = np.zeros((n_ex, len(FEATURE_ORDER)))
    X_ex[:, f["packet_rate"]]      = rng.normal(400,   80,    n_ex).clip(100, 1000)
    X_ex[:, f["byte_rate"]]        = rng.normal(80000, 15000, n_ex).clip(20000, 200000)
    X_ex[:, f["unique_dst_ports"]] = rng.randint(1, 4, n_ex).astype(float)
    X_ex[:, f["unique_dst_ips"]]   = rng.randint(1, 5, n_ex).astype(float)
    X_ex[:, f["syn_ratio"]]        = rng.beta(2,  10, n_ex)
    X_ex[:, f["rst_ratio"]]        = rng.beta(1,  15, n_ex)
    X_ex[:, f["failed_auth_rate"]] = rng.beta(1,  10, n_ex)
    X_ex[:, f["open_port_count"]]  = rng.randint(1, 4, n_ex).astype(float)
    X_ex[:, f["cve_count"]]        = rng.randint(0, 4, n_ex).astype(float)
    X_ex[:, f["outbound_ratio"]]   = rng.beta(20, 1, n_ex).clip(0, 1)
    X_ex[:, f["night_activity"]]   = rng.beta(3,  5, n_ex)
    X_ex[:, f["protocol_entropy"]] = rng.normal(1.5, 0.4, n_ex).clip(0, 3)

    X = np.vstack([X_normal, X_ps, X_c2, X_ex])
    y = np.concatenate([
        np.zeros(N, dtype=int),
        np.ones(n_anomalous, dtype=int),
    ])
    return X, y
