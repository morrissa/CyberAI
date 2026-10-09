


"""Read-only TCP connection monitor: anomaly ensemble -> rule explanations."""
import csv
import ipaddress
import time
from collections import Counter, defaultdict
from datetime import datetime

import numpy as np
import psutil
from sklearn.ensemble import IsolationForest
from sklearn.neighbors import LocalOutlierFactor
from sklearn.preprocessing import StandardScaler
from sklearn.svm import OneClassSVM

# Edit these settings here, then run: python live_network_threat_monitor.py
BASELINE_SAMPLES = 10
MONITOR_SAMPLES = 30
INTERVAL_SECONDS = 3
OUTPUT_FILE = "output_network_findings.csv"
MIN_BASELINE_ROWS = 15
VOTES_REQUIRED = 2  # Majority of 3 different anomaly detectors.
COMMON_PORTS = {53, 80, 123, 443, 465, 587, 993, 995, 8080, 8443}
COLUMNS = ("Time detected", "Program name", "Process ID", "Finding",
           "Why it was flagged", "Connections now", "Typical connections",
           "Remote computers", "Public internet hosts", "Uncommon ports",
           "Models agreeing", "Suggested next step")

def is_public(address):
    try:
        return ipaddress.ip_address(address.split("%")[0]).is_global
    except ValueError:
        return False

def snapshot():
    """Read established TCP sockets; aggregate by owning process."""
    groups = defaultdict(list)
    try:
        sockets = psutil.net_connections(kind="tcp")
    except psutil.AccessDenied:
        print("Access denied: try Command Prompt as Administrator.")
        return []
    for socket in sockets:
        if (socket.pid is not None and socket.raddr
                and socket.status == psutil.CONN_ESTABLISHED):
            groups[socket.pid].append(socket)
    rows = []
    for pid, connections in groups.items():
        try:
            process = psutil.Process(pid).name()
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            process = "unknown"
        destinations = {(s.raddr.ip, s.raddr.port) for s in connections}
        hosts = {ip for ip, _ in destinations}
        rows.append({"pid": pid, "process": process,
                     "connections": len(connections), "remote_hosts": len(hosts),
                     "public_hosts": sum(map(is_public, hosts)),
                     "unusual_ports": sum(port not in COMMON_PORTS
                                          for _, port in destinations)})
    return rows

def features(rows):
    keys = ("connections", "remote_hosts", "public_hosts", "unusual_ports")
    return np.log1p(np.array([[r[k] for k in keys] for r in rows], dtype=float))

def train_ensemble(baseline):
    if len(baseline) < MIN_BASELINE_ROWS:
        raise ValueError("Too few baseline records. Increase BASELINE_SAMPLES.")
    x = features(baseline)
    if np.unique(x, axis=0).shape[0] < 3:
        raise ValueError("Baseline lacks variety; collect more normal activity.")
    scaler = StandardScaler().fit(x)
    x = scaler.transform(x)
    models = {
        "IsolationForest": IsolationForest(contamination=0.1, random_state=42),
        "LocalOutlierFactor": LocalOutlierFactor(n_neighbors=min(15, len(x)-1),
                                                contamination=0.1, novelty=True),
        "OneClassSVM": OneClassSVM(nu=0.1, gamma="scale"),
    }
    for model in models.values():
        model.fit(x)
    return scaler, models

def ensemble(rows, scaler, models):
    """Run each detector; keep only rows with at least two outlier votes."""
    if not rows:
        return []
    x = scaler.transform(features(rows))
    predictions = {name: model.predict(x) for name, model in models.items()}
    results = []
    for index, row in enumerate(rows):
        flagged = [name for name, p in predictions.items() if p[index] == -1]
        if len(flagged) >= VOTES_REQUIRED:
            results.append((row, flagged))
    return results

def infer(row, typical):
    """Explain only majority-voted outliers using observable evidence."""
    facts = set()
    if row["connections"] >= 20:
        facts.add("many_connections")
    if row["remote_hosts"] >= 10:
        facts.add("many_destinations")
    if row["unusual_ports"] >= 3:
        facts.add("uncommon_ports")
    if row["public_hosts"] >= 10:
        facts.add("many_public_hosts")
    if typical is not None and row["connections"] >= max(5, typical * 2):
        facts.add("more_than_usual")
    rules = [({"many_connections", "many_destinations"}, "high_activity"),
             ({"many_destinations", "many_public_hosts"}, "wide_internet_use"),
             ({"high_activity", "uncommon_ports"}, "unusual_high_activity")]
    while True:
        additions = {conclusion for conditions, conclusion in rules
                     if conditions <= facts}
        if additions <= facts:
            break
        facts |= additions
    reasons = []
    if "many_connections" in facts:
        reasons.append(f"{row['connections']} simultaneous connections (20+ threshold)")
    if "many_destinations" in facts:
        reasons.append(f"connections to {row['remote_hosts']} different computers")
    if "uncommon_ports" in facts:
        reasons.append(f"{row['unusual_ports']} connections using less-common ports")
    if "many_public_hosts" in facts:
        reasons.append(f"{row['public_hosts']} public internet destinations")
    if "more_than_usual" in facts:
        reasons.append(f"more than twice its typical {typical:g} connections")
    if "high_activity" in facts:
        reasons.append("both connection count and destination count are high")
    if "wide_internet_use" in facts:
        reasons.append("many destinations are on the public internet")
    if "unusual_high_activity" in facts:
        reasons.append("high activity includes less-common ports")
    return "; ".join(reasons) or "connection pattern differs from the initial baseline"

def process_baselines(rows):
    """Median active connections for each named program during baseline."""
    by_program = defaultdict(list)
    for row in rows:
        by_program[row["process"]].append(row["connections"])
    return {name: float(np.median(counts)) for name, counts in by_program.items()}

def main():
    print("Collecting local TCP baseline (no external services)...")
    baseline = []
    for i in range(BASELINE_SAMPLES):
        rows = snapshot()
        baseline.extend(rows)
        print(f"Baseline {i+1}/{BASELINE_SAMPLES}: {len(rows)} processes")
        if i < BASELINE_SAMPLES - 1:
            time.sleep(INTERVAL_SECONDS)
    try:
        scaler, models = train_ensemble(baseline)
    except ValueError as error:
        print(f"Cannot train anomaly ensemble: {error}")
        return
    print("Three detectors ready. A finding requires 2 or 3 to agree.")
    print("Checking live connections. A finding is NOT proof of an attack.\n")
    typical = process_baselines(baseline)
    totals = Counter()
    with open(OUTPUT_FILE, "w", newline="", encoding="utf-8") as file:
        writer = csv.DictWriter(file, fieldnames=COLUMNS)
        writer.writeheader()
        for i in range(MONITOR_SAMPLES):
            rows = snapshot()
            flagged = ensemble(rows, scaler, models)
            for row, votes in flagged:
                normal = typical.get(row["process"])
                reason = infer(row, normal)  # Only ensemble outliers get explanations.
                comparison = f"{normal:g}" if normal is not None else "No earlier data"
                record = {"Time detected": datetime.now().isoformat(timespec="seconds"),
                          "Program name": row["process"], "Process ID": row["pid"],
                          "Finding": "Unusual activity - review recommended",
                          "Why it was flagged": reason,
                          "Connections now": row["connections"],
                          "Typical connections": comparison,
                          "Remote computers": row["remote_hosts"],
                          "Public internet hosts": row["public_hosts"],
                          "Uncommon ports": row["unusual_ports"],
                          "Models agreeing": f"{len(votes)} of 3",
                          "Suggested next step": "Check if you recognise this program; do not block it automatically"}
                writer.writerow(record)
                totals[row["process"]] += 1
                print(f"\n[PLEASE REVIEW] {row['process']} (process ID {row['pid']})")
                print(f"  Why: {reason}")
                print(f"  Connections: {row['connections']} now; {comparison} typical")
                print(f"  Detection: {len(votes)} of 3 models found this unusual")
                print("  Next: Check whether you recognise this program; don't block it automatically.")
            print(f"Check {i+1}/{MONITOR_SAMPLES}: "
                  f"{len(rows)} active programs, {len(flagged)} flagged for review")
            file.flush()
            if i < MONITOR_SAMPLES - 1:
                time.sleep(INTERVAL_SECONDS)
    print(f"\nFinished: {sum(totals.values())} findings saved to {OUTPUT_FILE}")
    print("An outlier is not proof of malicious activity; investigate before acting.")

if __name__ == "__main__":
    main()
