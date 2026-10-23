"""Reproducible synthetic network-flow dataset for CyberSentinel AI.

Addresses come from RFC 5737 documentation ranges. A share of the attack rows
is generated in a low-intensity "stealth" form whose feature ranges overlap
with normal traffic, so the classification task is not trivially separable.
The ground-truth label is assigned by the generator, not by any real capture.
"""
import numpy as np
import pandas as pd

CLASSES = [
    "Normal Traffic", "DDoS / DoS", "Port Scanning / Reconnaissance",
    "Brute-Force Login", "Suspicious Malware-Related Traffic",
    "Suspicious Phishing Indicators", "Data Exfiltration / Unusual Outbound Traffic",
]
COLUMNS = ["timestamp", "source_ip", "destination_ip", "source_port", "destination_port",
           "protocol", "duration", "packet_count", "bytes_sent", "bytes_received",
           "failed_login_count", "unique_destination_ports", "outbound_inbound_ratio", "label"]
STEALTH_RATE = 0.15


def _row(c, rs, stealth):
    ri = lambda a, b: int(rs.randint(a, b + 1))
    rf = lambda a, b: float(rs.uniform(a, b))
    pick = lambda xs: xs[ri(0, len(xs) - 1)]
    o = dict(protocol="TCP", failed_login_count=0, unique_destination_ports=1)
    if c == 0:
        o["protocol"] = "TCP" if rs.rand() < .7 else "UDP"
        o["destination_port"] = pick([80, 443, 53, 22, 25])
        busy = stealth  # busy-but-legitimate traffic
        o["duration"] = rf(.5, 120 if busy else 60)
        o["packet_count"] = ri(300, 1500) if busy else ri(5, 300)
        o["bytes_sent"] = ri(50000, 500000) if busy else ri(500, 50000)
        o["bytes_received"] = ri(int(max(1000, o["bytes_sent"] * .3)), int(o["bytes_sent"] * 4 + 2000))
        o["failed_login_count"] = ri(0, 2) if busy else (1 if rs.rand() < .1 else 0)
        o["unique_destination_ports"] = ri(1, 8) if busy else ri(1, 3)
    elif c == 1:
        o["protocol"] = pick(["UDP", "TCP"]); o["destination_port"] = pick([80, 443, 53])
        o["duration"] = rf(5, 60) if stealth else rf(1, 20)
        o["packet_count"] = ri(800, 6000) if stealth else ri(5000, 50000)
        o["bytes_sent"] = ri(50000, 400000) if stealth else ri(100000, 900000)
        o["bytes_received"] = ri(0, 8000) if stealth else ri(0, 2000)
        o["unique_destination_ports"] = ri(1, 2)
    elif c == 2:
        o["destination_port"] = ri(1, 1024)
        o["duration"] = rf(5, 60) if stealth else rf(.1, 5)
        o["packet_count"] = ri(10, 300) if stealth else ri(20, 120)
        o["bytes_sent"] = o["packet_count"] * ri(40, 60); o["bytes_received"] = ri(0, 500)
        o["unique_destination_ports"] = ri(6, 25) if stealth else ri(20, 200)
    elif c == 3:
        o["destination_port"] = pick([22, 3389, 21])
        o["duration"] = rf(20, 200) if stealth else rf(30, 300)
        o["packet_count"] = ri(60, 400); o["bytes_sent"] = ri(5000, 40000); o["bytes_received"] = ri(3000, 30000)
        o["failed_login_count"] = ri(2, 8) if stealth else ri(6, 60)
    elif c == 4:
        o["destination_port"] = pick([443, 8080, 4444]) if stealth else pick([4444, 6667, 31337, 1337])
        o["duration"] = rf(120, 900) if stealth else rf(300, 3600)
        o["packet_count"] = ri(30, 200)
        o["bytes_sent"] = ri(500, 8000) if stealth else ri(500, 3000); o["bytes_received"] = ri(500, 3000)
        o["unique_destination_ports"] = ri(1, 2)
    elif c == 5:
        o["destination_port"] = pick([443, 80]) if stealth else pick([8080, 8443, 8888])
        o["duration"] = rf(1, 12) if stealth else rf(1, 6)
        o["packet_count"] = ri(8, 25); o["bytes_sent"] = ri(800, 4000); o["bytes_received"] = ri(2000, 9000)
        o["failed_login_count"] = ri(0, 2) if stealth else ri(1, 2)
    else:
        o["destination_port"] = pick([443, 21, 22, 53])
        o["duration"] = rf(120, 1800); o["packet_count"] = ri(500, 5000)
        o["bytes_sent"] = ri(10**6, 6 * 10**6) if stealth else ri(5 * 10**6, 8 * 10**7)
        o["bytes_received"] = ri(20000, 300000) if stealth else ri(10000, 500000)
    o["duration"] = round(o["duration"], 2)
    o["source_port"] = ri(1025, 65535)
    o["outbound_inbound_ratio"] = round(o["bytes_sent"] / max(o["bytes_received"], 1), 2)
    o["label"] = CLASSES[c]
    return o


def generate(seed=42, per_class=80):
    rs = np.random.RandomState(seed)
    ip = lambda: ["198.51.100.", "203.0.113.", "192.0.2."][rs.randint(0, 3)] + str(rs.randint(1, 255))
    order = np.array([i % 7 for i in range(per_class * 7)])
    rs.shuffle(order)
    base = pd.Timestamp("2026-10-23T00:00:00Z")
    rows = []
    for i, c in enumerate(order):
        r = _row(int(c), rs, rs.rand() < STEALTH_RATE)
        r["timestamp"] = (base + pd.Timedelta(seconds=40 * i)).isoformat().replace("+00:00", "Z")
        r["source_ip"], r["destination_ip"] = ip(), ip()
        rows.append(r)
    return pd.DataFrame(rows)[COLUMNS]


if __name__ == "__main__":
    df = generate()
    df.to_csv("dataset.csv", index=False)
    print(df.label.value_counts())
