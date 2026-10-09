# Live Network Threat Monitor

A small, **read-only Windows network monitor** that identifies unusual *active TCP connection patterns* using a three-model machine-learning ensemble. Only processes flagged by **at least two models** pass to a forward-chaining rule engine, which produces a plain-English explanation. Findings appear in the terminal and in `output_network_findings.csv`.

The full application is **199 lines of Python**, including comments and blank lines. It does **not** use reinforcement learning, inspect packet contents, block connections, or claim to identify malware conclusively.

## Requirements

- Windows with Python 3.10+ (and supported wheels for installed packages)
- `psutil`, `numpy`, and `scikit-learn`
- Permission to inspect local TCP connections. Some process information may require launching Command Prompt as Administrator.

## Installation and run

In **Command Prompt** (CMD):

```cmd
cd C:\Users\sam_a\Desktop\CyberAI
python -m pip install psutil numpy scikit-learn
python live_network_threat_monitor.py
```

The pip package is named **`scikit-learn`**, although its Python import is `sklearn`.

No command-line flags or CyberBattleSim installation are needed. Adjust configuration constants at the top of `live_network_threat_monitor.py` instead.

## Configuration

| Name | Default | Meaning |
|---|---:|---|
| `BASELINE_SAMPLES` | `10` | Number of snapshots used for fitting the anomaly models. |
| `MONITOR_SAMPLES` | `30` | Number of snapshots evaluated after fitting. |
| `INTERVAL_SECONDS` | `3` | Pause between snapshots, in seconds. |
| `OUTPUT_FILE` | `output_network_findings.csv` | CSV report filename, relative to your current working directory. |
| `MIN_BASELINE_ROWS` | `15` | Minimum total process observations required to train the models. |
| `VOTES_REQUIRED` | `2` | Minimum outlier votes out of 3 for further inference and reporting. |
| `COMMON_PORTS` | `{53, 80, 123, 443, 465, 587, 993, 995, 8080, 8443}` | Remote ports treated as common by one feature; not a definitive assessment of safety. |

Model parameters are set within `train_ensemble`: Isolation Forest `contamination=0.1`, LOF `contamination=0.1` and `n_neighbors=min(15, len(x)-1)`, One-Class SVM `nu=0.1, gamma="scale"`. The code fixes the Isolation Forest random seed at 42.

At the defaults, baseline acquisition uses 10 snapshots and monitoring uses 30; pauses occur **between**, not after, snapshots. The output file is overwritten on each run.

## Workflow

```text
Windows active TCP sockets (psutil)
   ↓
Group established remote TCP connections by process ID
   ↓
Extract 4 numeric features per process
   ↓
log1p transformation → StandardScaler
   ↓
Isolation Forest + Local Outlier Factor + One-Class SVM
   ↓
Majority vote: fewer than 2 outliers → no finding
                2 or 3 outliers → forward-chaining inference
   ↓
Plain-English reasons + baseline comparison
   ↓
Console output + output_network_findings.csv
```

### Data collection: `snapshot()`

The script uses `psutil.net_connections(kind="tcp")`. It considers only **established TCP connections** with a remote endpoint and known owning PID. It groups connections by PID and retrieves the process name where permitted.

The four raw features, each calculated per process snapshot, are:

1. **Connections**: total established TCP connections.
2. **Remote hosts**: distinct remote IP addresses.
3. **Public hosts**: number of those remote IP addresses classified as globally reachable with Python's `ipaddress` library.
4. **Unusual ports**: number of distinct remote IP/port pairs whose destination port is not in the configured common-port set.

These features describe network *connection patterns*, not packet content or confirmed malicious behaviour.

### Preprocessing: `features()`

Each count is transformed by `log1p(x) = ln(1 + x)` to reduce the influence of very large counts. A `StandardScaler` is fit on baseline data and reused during monitoring so all three models receive the same scaled feature representation.

### Ensemble: `train_ensemble()` and `ensemble()`

Each model is fit on initial local snapshots; labels are not required.

| Model | Why it was chosen | Main limitation |
|---|---|---|
| **Isolation Forest** | Randomly partitions feature space; unusual points often isolate in fewer splits. Efficient general-purpose anomaly detector. | Results depend on the baseline and contamination setting. |
| **Local Outlier Factor (LOF)** | Compares local sample density against neighbours, helping detect points that are unusual relative to nearby observations. | Sensitive to scaling, neighbourhood size, repetitive data and small samples. `novelty=True` lets it predict on later snapshots. |
| **One-Class SVM** | Learns a boundary of the baseline feature distribution, providing a different geometric view of novelty. | Sensitive to feature scaling, kernel hyperparameters and baseline quality. |

Each `.predict()` returns **`1` for inlier** or **`-1` for outlier**. A majority vote (`VOTES_REQUIRED=2`) determines whether a process snapshot is forwarded for explanation.

The detectors use the **same** four features and therefore their votes are *correlated*, not independent evidence of an attack. Majority voting is an easy-to-understand design choice, not a guarantee of improved accuracy.

### Inference: `infer(row, typical)`

Only majority-flagged outliers are sent to `infer()`. The inference engine is **symbolic**, not another trained ML model. It begins with facts generated by thresholds and, where available, the median connection count recorded for that **process name** during the initial baseline.

**Initial facts**:

| Fact | Rule for adding it |
|---|---|
| `many_connections` | `connections >= 20` |
| `many_destinations` | `remote_hosts >= 10` |
| `uncommon_ports` | `unusual_ports >= 3` |
| `many_public_hosts` | `public_hosts >= 10` |
| `more_than_usual` | A baseline median exists and `connections >= max(5, 2 × median)` |

**Forward-chaining rules**:

```text
many_connections AND many_destinations → high_activity
many_destinations AND many_public_hosts → wide_internet_use
high_activity AND uncommon_ports      → unusual_high_activity
```

Rules are applied repeatedly until no new facts can be derived (a **fixed point**). For example, a process might first satisfy `many_connections` and `many_destinations`, producing `high_activity`; when `uncommon_ports` is also present, the next inference round derives `unusual_high_activity`.

The final explanation converts the facts into plain English, such as “32 simultaneous connections (20+ threshold); connections to 14 different computers; both connection count and destination count are high.” If no threshold triggers, it says “connection pattern differs from the initial baseline.”

This **does not** explain the internal decision path of the three ML models. It supplies interpretable observations that accompany a statistical outlier vote.

### Process baseline comparison: `process_baselines()`

This function calculates the median active connection count for each **process name** over the baseline period. The report then contrasts current connections with the median where available. Different processes sharing the same executable name are grouped together; this is not a per-PID or long-term behavioural profile.

## Output

### Console example (illustrative)

```text
Three detectors ready. A finding requires 2 or 3 to agree.
Checking live connections. A finding is NOT proof of an attack.

[PLEASE REVIEW] example.exe (process ID 4521)
  Why: 32 simultaneous connections (20+ threshold); connections to 14 different computers; both connection count and destination count are high
  Connections: 32 now; 4 typical
  Detection: 3 of 3 models found this unusual
  Next: Check whether you recognise this program; don't block it automatically.
Check 1/30: 12 active programs, 1 flagged for review
```

### CSV report

The output file is **`output_network_findings.csv`** and contains **only majority-voted outlier observations**. Its columns are:

- `Time detected`: timestamp of the snapshot.
- `Program name`: owning process name when available.
- `Process ID`: Windows PID.
- `Finding`: fixed plain-English review status.
- `Why it was flagged`: inferred observations and conclusions.
- `Connections now`: current established TCP connection count.
- `Typical connections`: baseline median for the process name or “No earlier data”.
- `Remote computers`: number of distinct remote IPs.
- `Public internet hosts`: number of globally reachable remote IPs.
- `Uncommon ports`: number of remote endpoint pairs outside the configured common-port set.
- `Models agreeing`: number of ensemble outlier votes, e.g. “2 of 3”.
- `Suggested next step`: non-disruptive advice to investigate.

Repeated snapshots can create repeated rows for the same PID. Open the CSV in Excel to filter by program, PID or timestamp. If there are no findings, the file still contains its header row.

## Safety and limitations

- **Read-only**: no packet interception, process termination, firewall changes, automatic blocking, uploads, or external API calls.
- **Not malware detection**: connection outliers can be legitimate software updates, browsers, cloud-sync tools, or corporate applications.
- **Short, unverified baseline**: it can contain unusual activity and does not capture different daily usage patterns.
- **Four coarse features only**: no DNS histories, payload inspection, executable signatures, certificates, connection duration or threat intelligence.
- **TCP established sockets only**: UDP, listening ports, unsuccessful connection attempts and short-lived connections between samples are outside scope.
- **Permission limits**: Windows may restrict process and connection information. If nothing appears, try running CMD as Administrator only if you're comfortable doing so.
- **Thresholds are illustrative**: fixed thresholds and majority voting have not been calibrated using labelled benign/malicious data.
- **No reinforcement learning**: the ML component is unsupervised anomaly detection; inference is rule-based forward chaining.

## Code map

| Function | Responsibility |
|---|---|
| `is_public()` | Determine whether an IP is globally reachable. |
| `snapshot()` | Collect and aggregate live established TCP sockets. |
| `features()` | Turn process observations into four log-transformed numbers. |
| `train_ensemble()` | Scale baseline features and fit the three models. |
| `ensemble()` | Run all three models and apply majority voting. |
| `infer()` | Derive symbolic conclusions and plain-English reasons. |
| `process_baselines()` | Compute per-process-name typical connection counts. |
| `main()` | Orchestrate collection, training, monitoring, terminal output and CSV reporting. |

## Troubleshooting

**`ModuleNotFoundError: No module named 'psutil'`**

```cmd
python -m pip install psutil
```

**`ModuleNotFoundError: No module named 'sklearn'`**

```cmd
python -m pip install scikit-learn
```

Do *not* install the deprecated package named `sklearn` from pip.

**`Access denied`**: The OS may restrict socket/process inspection. Try an elevated Command Prompt if appropriate.

**Too few baseline records**: Increase `BASELINE_SAMPLES`, or collect the baseline while some legitimate internet activity is present.

**No findings**: This is possible and does not prove the network is safe; the ensemble only reports observations flagged by at least two detectors.

## Future work

Potential extensions include comparing ML-only versus inference-only output, explaining feature deviations from a historical baseline, suppressing repeated alerts, persisting an approved baseline, and evaluating detections with labelled records. A reinforcement-learning response agent would require a separately justified action space and trustworthy feedback/reward model.
