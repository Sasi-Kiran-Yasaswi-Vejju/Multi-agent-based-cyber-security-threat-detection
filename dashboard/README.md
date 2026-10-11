# Autonomous Multi-Agent Cybersecurity Threat Detection & Response System
## Interactive SOC Dashboard & Demonstration Platform

**Course**: 23CSE401 – Foundations of Artificial Intelligence  
**Institution**: Amrita Vishwa Vidyapeetham  
**Authors**:
- **Nanthakumaran** (`CB.SC.U4CSE23341`) — *Agent 1: Intrusion Detection Agent (DETECT)*
- **Dhinesh chandra** (`CB.SC.U4CSE23310`) — *Agent 2: Threat & Security Analysis (ANALYZE)*
- **Vejju Sasi Kiran Yasaswi** (`CB.SC.U4CSE23356`) — *Agent 3: Threat Intelligence (ENRICH) & Agent 4: Risk & Response Planning (ASSESS + PLAN)*

---

## 🚀 How to Launch the Dashboard

### Option 1: One-Command Launcher (Opens Browser Automatically)
From the workspace root directory:
```bash
python run_system.py --ui
```
or
```bash
python dashboard/server.py 8000
```
Then navigate to: **`http://localhost:8000/`**

### Option 2: Standalone Zero-Server Execution
You can also open `dashboard/index.html` directly in any modern web browser (Chrome, Edge, Firefox, Safari). The client incorporates a dual-mode fallback state machine with identical scenario data, graph rendering, and search calculations.

---

## 🎨 Visual Aesthetics & SOC Design Language

- **Theme**: Modern Cybersecurity SOC Console — restrained, data-dense, dark obsidian canvas (`#0B0F17`) with cool cyan (`#38BDF8`), amber warning (`#F59E0B`), crimson critical (`#EF4444`), and emerald normal (`#10B981`).
- **Light Theme**: Crisp cloud/chalk canvas (`#F8FAFC`) with balanced slate borders (`#E2E8F0`) and dark navy text (`#0F172A`).
- **Contrast & Hierarchy**: WCAG AAA compliant with typography powered by *Inter* and *JetBrains Mono*.
- **Glassmorphism**: Subtle `backdrop-filter: blur(16px)` with crisp 1px borders and smooth cubic-bezier transitions.
- **Theme Switcher**: Top-right toggle with local storage persistence.

---

## 🤖 The 4 Specialized Agents & Multi-Agent Architecture

1. **Agent 1: Intrusion Detection Agent (DETECT)**
   - *Lead*: Nanthakumaran (`CB.SC.U4CSE23341`)
   - *Model*: Supervised Random Forest Classifier (100 trees, max depth 12).
   - *Perception*: Ingests raw network packet sizes, protocols, failed login attempts, session durations, and IP reputation scores.
   - *Smart Routing*: If predicted as `NORMAL` with confidence $\ge 0.80$, triggers an **Early Exit**, pruning Agents 2, 3, and 4 and saving 75% computational overhead.

2. **Agent 2: Threat & Security Analysis (ANALYZE)**
   - *Lead*: Dhinesh chandra (`CB.SC.U4CSE23310`)
   - *Engine*: Symbolic Knowledge Reasoning & CIA Triad Impact Mapping (Confidentiality, Integrity, Availability).
   - *Output*: Base severity score (0–10), extracted Indicators of Compromise (IoCs), and structured `INTELLIGENCE_REQUEST` queries.

3. **Agent 3: Threat Intelligence Engine (ENRICH)**
   - *Lead*: Vejju Sasi Kiran Yasaswi (`CB.SC.U4CSE23356`)
   - *Knowledge*: MITRE ATT&CK STIX 2.0 Graph ($G = (V, E)$, 2,510 active nodes, 43,950 directed edges) + CISA KEV (1,734 actively exploited CVEs).
   - *Search*: Hybrid search (Keyword matching + Semantic TF-IDF Cosine Similarity + BFS graph traversal to depth $d=2$).

4. **Agent 4: Risk Assessment & Response Planning (ASSESS + PLAN)**
   - *Lead*: Vejju Sasi Kiran Yasaswi (`CB.SC.U4CSE23356`)
   - *Risk Calculation*: Deterministic composite risk score:
     $$\text{Risk} = 0.25 S_{\text{sev}} + 0.20 S_{\text{asset}} + 0.20 S_{\text{exploit}} + 0.15 S_{\text{impact}} + 0.10 S_{\text{exposure}} + 0.10 S_{\text{conf}}$$
   - *Search Algorithm*: Informed cost-optimal A\* search over the state-space Response Graph ($f(n) = g(n) + h(n)$).
   - *Dynamic Feedback Loop*: When target asset context is missing, dispatches a `CLARIFICATION_REQUEST` to Agent 2 and recalculates upon receiving `CLARIFICATION_RESPONSE`.

---

## 🎬 Dashboard Core Modules & Views

### Tab 1: Interactive Incident Scenario Simulator
- **Preset 1 (Credential Brute Force)**: Full 4-agent containment workflow $\to$ `BLOCK_SOURCE_IP` $\to$ credential rotation.
- **Preset 2 (CISA KEV CVE-2026-88779)**: Priority elevation to `CRITICAL` with mandated CISA BOD 26-04 patch directives.
- **Preset 3 (Legitimate User Session)**: Smart Routing Early Exit at Agent 1, visually pruning downstream agents and saving 3 invocations (75% savings).
- **Preset 4 (Anomalous Intrusion / Missing Context)**: Backward clarification loop between Agent 4 and Agent 2.
- **Custom Scenario Creator**: Modal allowing customized packet sizes, protocols, failed login counts, session durations, and CVE exploit IDs.
- **JSON Telemetry Exporter**: Exports complete serialized `IncidentState` envelopes.

### Tab 2: Animated Multi-Agent Collaboration Graph
- Interactive Node-Link Canvas representing Central Orchestrator and all 4 specialized agents.
- **Animated Message Packets**: Flowing glowing particles along directed quadratic bezier curves (`ALERT`, `INTELLIGENCE_REQUEST`, `INTELLIGENCE_RESPONSE`, `FINAL_DECISION`).
- **Backward Clarification Loop**: Distinct dashed amber feedback lines and reverse particles.
- **Pruned Pathways**: Greyed out links marked with `[PRUNED - SAVED]` badges for benign traffic.
- **Scrubber Controls**: Play, Pause, Step-by-Step Forward, Step Back, Reset, and Speed multiplier (0.5x, 1x, 2x).
- **Interactive Node Inspector**: Click on any node to view real-time PEAS profile, sensors, actuators, and confidence scores.

### Tab 3: Reasoning & A* Search Interactive Laboratory
- **Interactive Risk Weight Sliders**: Real-time slider recalculation across all 6 risk factors with immediate tier badges (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
- **Academic Callout**: Details why deterministic formulas prevent generative LLM hallucinations in SOC operations.
- **BFS vs. A\* Search Comparison**: Side-by-side comparison on the formal Response Graph showing A\* finding the provably cost-optimal path ($\text{Cost} = 10.0$ vs BFS $\text{Cost} = 12.0$) with 50% fewer node expansions and 16.7% operational cost savings.
- **Mathematical Proofs**: Explicit proofs for heuristic admissibility ($h(n) \le h^*(n)$) and consistency ($h(u) \le c(u, a, v) + h(v)$).

### Tab 4: System Evaluation & Benchmark Suite
- **Model Perception Benchmark**: 2x2 Confusion Matrix visualizer (TN: 1,055, FP: 0, FN: 217, TP: 636) with Accuracy ($88.63\%$), Precision ($100.00\%$), Recall ($74.56\%$), and False Positive Rate ($0.00\%$).
- **Academic Defense**: In-depth analysis of the Base Rate Fallacy and SOC alert fatigue.
- **Algorithmic Micro-Benchmark**: Live "Run 1,000 Iterations" button executing real BFS vs A\* benchmarks in microseconds.
- **Automated Test Suite Status**: Visual checklist of all 46 automated unit tests passing across all 8 modules with a "Re-run Tests" trigger.
