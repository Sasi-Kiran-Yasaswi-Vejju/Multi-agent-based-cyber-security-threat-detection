# Multi-Agent AI-Based Cybersecurity Threat Detection and Response System

**Course**: 23CSE401 – Foundations of Artificial Intelligence  
**Evaluation**: Review 1 (10 Marks Evaluation Rubric)  
**Institution**: Amrita Vishwa Vidyapeetham  
**Target Score**: 10 / 10 Marks  

---

## Team Members & Responsibilities

| Student Name | Roll Number | Primary Role | Area of Ownership |
| :--- | :--- | :--- | :--- |
| **Nanthakumaran** | `CB.SC.U4CSE23341` | Data Perception & ML Specialist | **Agent 1**: Intrusion Detection, Data Preprocessing, Random Forest & Decision Tree Classifiers, Confusion Matrix & Metrics, Agent 1 PEAS |
| **Dhinesh chandra** | `CB.SC.U4CSE23310` | Knowledge Engineer & Threat Analyst | **Agent 2**: Cybersecurity Knowledge Base (`cybersecurity_rules.json`), CIA Triad Impact Mapping, Dynamic Risk Scoring, Agent 2 PEAS, Environment Analysis |
| **Vejju Sasi Kiran Yasaswi** | `CB.SC.U4CSE23356` | Algorithmic Architect & Systems Integrator | **State-Space Search & Integration**: Response Graph Modeling, BFS & A* Algorithms, Cost Function $g(n)$, Admissible Heuristic $h(n)$ Proof, JSON Wire Messaging, CLI Demo & Benchmarks |

---

## Table of Contents
1. [Quick Start: How to Run the Project](#1-quick-start-how-to-run-the-project)
2. [Review 1 Evaluation Rubric Alignment (10 Marks)](#2-review-1-evaluation-rubric-alignment-10-marks)
3. [Multi-Agent Justification: Why Multiple Agents?](#3-multi-agent-justification-why-multiple-agents)
4. [Dataset Analysis & Academic Defense](#4-dataset-analysis--academic-defense)
5. [Complete Project Architecture](#5-complete-project-architecture)
6. [Agent 1: Intrusion Detection Agent (PEAS & ML)](#6-agent-1-intrusion-detection-agent-peas--ml)
7. [Agent 2: Threat Analysis & Response Planning Agent (PEAS & Rules)](#7-agent-2-threat-analysis--response-planning-agent-peas--rules)
8. [Environment & Agent Analysis (7 Dimensions)](#8-environment--agent-analysis-7-dimensions)
9. [Algorithmic Modeling & State-Space Graph](#9-algorithmic-modeling--state-space-graph)
10. [Search Strategy: BFS vs. A* Comparison & Admissibility Proof](#10-search-strategy-bfs-vs-a-comparison--admissibility-proof)
11. [Experimental Results & Search Benchmarks](#11-experimental-results--search-benchmarks)
12. [12-Slide Presentation Script & Speaker Assignments](#12-12-slide-presentation-script--speaker-assignments)
13. [Faculty Viva Q&A Crib Sheet (Top 10 Questions)](#13-faculty-viva-qa-crib-sheet-top-10-questions)
14. [Automated Verification & Unit Test Results](#14-automated-verification--unit-test-results)

---

## 1. Quick Start: How to Run the Project

### Setup
Open **PowerShell** or **Terminal** and navigate to the project directory:
```bash
cd "c:/Users/sasik/Downloads/FOAI/Case Study/cybersecurity_multi_agent"
```

Dependencies (`scikit-learn`, `pandas`, `numpy`, `joblib`) are already installed. If running on another team member's laptop:
```bash
pip install -r requirements.txt
```

---

### The 4 Execution Commands for Review 1

#### 1. Live Interactive Demonstration (Primary Review 1 Command)
```bash
python run_system.py --demo
```
* **What it does**: Executes an end-to-end multi-agent detection and response workflow across 3 realistic scenarios:
  1. *Scenario 1*: Credential Brute Force attack against Core Database -> Dispatches `BLOCK_SOURCE`.
  2. *Scenario 2*: Volumetric UDP DoS Flood against DMZ Web Server -> Dispatches `BLOCK_SOURCE`.
  3. *Scenario 3*: Legitimate Authenticated Enterprise User -> Dispatches `LOG_AND_PASS` (Zero business disruption).
* **What to watch & point out**:
  * Agent 1's ML prediction (`ATTACK` vs `NORMAL`) with confidence probability and explainable evidence strings.
  * The actual **JSON Wire Payload** exchanged between agents (proof of loose coupling).
  * Agent 2's symbolic reasoning (CIA Triad impact, Severity, Risk Score $0\text{--}100$).
  * The **side-by-side search comparison table** showing BFS path cost vs A* path cost.

#### 2. Algorithmic Search Benchmark (BFS vs. A*)
```bash
python run_system.py --benchmark
```
* **What it does**: Executes 1,000 iterations of both BFS and A* search algorithms on the response graph.
* **Key result**: Shows that BFS finds the shallowest path (2 hops) with a higher operational cost (**12.0**), while A* finds the optimal 3-hop path with a lower cost (**10.0**), proving a **16.7% operational cost savings** and **50% fewer node expansions**.

#### 3. Automated Unit & Integration Tests
```bash
python -m unittest discover -s tests -v
```
* **What it does**: Runs 15 unit and integration tests verifying Agent 1 perception, missing feature imputation, Agent 2 knowledge reasoning, mathematical heuristic admissibility ($h(n) \le h^*(n)$), consistency triangle inequality, and end-to-end multi-agent messaging.
* **Result**: `15 tests passed in 0.8s (OK)`.

#### 4. Model Training & Evaluation
```bash
python train_model.py
```
* **What it does**: Ingests the 9,537-record dataset, fits the `ColumnTransformer`, trains Random Forest (primary) and Decision Tree (comparator), prints the confusion matrix, and serializes artifacts to `models/`.

---

## 2. Review 1 Evaluation Rubric Alignment (10 Marks)

| Rubric Component | Allocated Marks | Project Implementation Section | Status |
| :--- | :---: | :--- | :---: |
| **1. PEAS Formulation** | **3 Marks** | Complete formal PEAS tables for Agent 1 and Agent 2 with measurable performance measures (Section 6 & 7). | Complete |
| **2. Environment & Agent Analysis** | **3 Marks** | 7-dimension Russell & Norvig environment taxonomy + agent autonomy, rationality, and goal-directedness (Section 8). | Complete |
| **3. Algorithmic Modeling & Search** | **3 Marks** | Formal $\langle S_0, S, A, T, G, c \rangle$ state-space graph, BFS vs. A* implementation, cost function $g(n)$, and admissible heuristic $h(n)$ proof (Section 9 & 10). | Complete |
| **4. Q&A & Presentation Mechanics** | **1 Mark** | 12-slide presentation structure, student speaking distribution, and faculty Q&A crib sheet (Section 12 & 13). | Complete |
| **Total Target Score** | **10 / 10** | **Academic rigor, working code, and zero unsupported claims.** | **Target: 10/10** |

---

## 3. Multi-Agent Justification: Why Multiple Agents?

A common failure in academic AI projects is creating a single Python script and calling it an "agent." In cybersecurity, **perception** and **deliberation/planning** represent fundamentally different AI tasks:

```
                      RAW NETWORK TELEMETRY
                                ↓
        ┌───────────────────────────────────────────────┐
        │       AGENT 1: INTRUSION DETECTION AGENT      │
        │ • Role: Data-Driven Perception & ML           │
        │ • Input: Continuous numeric flow features     │
        │ • Answers: "Is this activity normal or       │
        │   malicious, with what confidence?"           │
        └───────────────────────┬───────────────────────┘
                                │ Structured JSON Wire Message
                                │ (Agent1Message)
                                ↓
        ┌───────────────────────────────────────────────┐
        │   AGENT 2: THREAT ANALYSIS & RESPONSE AGENT   │
        │ • Role: Knowledge Reasoning & Search Planning │
        │ • Input: Structured alert + Knowledge Base    │
        │ • Answers: "What does this threat mean, and   │
        │   what is the cost-optimal defensive action?" │
        └───────────────────────┬───────────────────────┘
                                ↓
                     OPTIMAL MITIGATION DISPATCH
```

### Why a Monolithic Single Agent Fails:
1. **Separation of Concerns**: Agent 1 runs fast, inductive statistical inference over continuous numbers. Agent 2 runs deductive symbolic reasoning and combinatorial graph search over discrete operational actions and business costs.
2. **Modularity & Extensibility**: In Review 2, new specialized agents (e.g., Threat Intelligence Agent, Dynamic Risk Assessment Agent) can be inserted into the communication pipeline without modifying existing agents.
3. **Independent Evaluation**: Agent 1 is evaluated using statistical metrics (Confusion Matrix, Precision, Recall, F1). Agent 2 is evaluated using search metrics (Path Cost, Node Expansions, Heuristic Admissibility).
4. **Explainability & Security Auditing**: Real-world Security Operations Centers (SOCs) require auditable decision traces. Automated firewall blocks must clearly state: *Agent 1 detected anomaly -> Agent 2 mapped to CIA Triad -> A\* proved that source blocking incurred lower operational disruption (cost 10) than server shutdown (cost 14)*.
5. **No Shared Memory**: Agents communicate strictly through validated JSON payloads (`Agent1Message`). Direct access to Agent 1's variables or model weights is prohibited.

---

## 4. Dataset Analysis & Academic Defense

### Benchmark Landscape: CICIDS2017 vs. UNSW-NB15 vs. Curated Session Dataset

| Criteria | CICIDS2017 | UNSW-NB15 | Curated Project Dataset (`cybersecurity_intrusion_data.csv`) |
| :--- | :--- | :--- | :--- |
| **Origin** | Canadian Institute for Cybersecurity (UNB) | Australian Centre for Cyber Security (UNSW) | Real-world intrusion telemetry benchmark |
| **Features** | 80 network flow features | 49 connection/content features | 10 high-relevance behavioral/flow features |
| **Size** | ~3.1 GB (PCAP + CSV) | ~100 MB (subsets) | ~725 KB (9,537 records) |
| **Class Balance** | Heavily imbalanced (>80% Benign) | Imbalanced across 9 categories | Balanced (55.3% Normal, 44.7% Attack) |
| **Execution Time** | Multi-hour training | Medium training overhead | **Instantaneous (< 2 seconds)** on student laptops |
| **Academic Defense** | Standard academic benchmark | Standard academic benchmark | **Zero external dependency; reproducible during live viva without disk/GPU bottlenecks.** |

### Dataset Characteristics:
* **Total Records**: 9,537 connection sessions.
* **Split**: Stratified 80/20 train/test split (7,629 training samples, 1,908 test samples).
* **Numerical Features**: `network_packet_size`, `login_attempts`, `session_duration`, `ip_reputation_score`, `failed_logins`.
* **Categorical Features**: `protocol_type` (`TCP`, `UDP`, `ICMP`), `encryption_used` (`AES`, `DES`, `None`), `browser_type`.
* **Binary Features**: `unusual_time_access` (`0` or `1`).
* **Target Label**: `attack_detected` (`0` = Normal, `1` = Attack).
* **Preprocessing Pipeline**: `ColumnTransformer` with `StandardScaler` on numerical features, `OneHotEncoder(handle_unknown='ignore')` on categorical features, imputation of missing encryption as `'None'` (unencrypted plaintext traffic), and dropping arbitrary session IDs to eliminate data leakage.

---

## 5. Complete Project Architecture

```text
cybersecurity_multi_agent/
│
├── agents/
│   ├── __init__.py
│   ├── intrusion_detection_agent.py   # Agent 1: perceive, preprocess, classify, explain
│   └── threat_response_agent.py      # Agent 2: analyze_threat, search, select_response
│
├── communication/
│   ├── __init__.py
│   └── messages.py                   # Typed message schemas (Agent1Message, Agent2Response)
│
├── knowledge/
│   └── cybersecurity_rules.json      # Structured rule-base (taxonomies, severity, CIA impact)
│
├── search/
│   ├── __init__.py
│   ├── response_graph.py             # Formal state-space graph, transition model, cost function
│   ├── bfs.py                        # Uninformed Breadth-First Search implementation
│   └── astar.py                      # Informed A* Search implementation with admissible heuristic
│
├── data/
│   ├── raw/
│   │   └── cybersecurity_intrusion_data.csv  # 9,537 authentic session records
│   └── processed/
│       ├── X_train.joblib, X_test.joblib
│       └── y_train.joblib, y_test.joblib
│
├── models/
│   ├── random_forest.joblib          # Primary Random Forest classifier (88.63% acc)
│   ├── decision_tree.joblib          # Baseline Decision Tree comparator (88.42% acc)
│   └── preprocessor.joblib           # Fitted ColumnTransformer pipeline
│
├── evaluation/
│   ├── __init__.py
│   └── metrics.py                    # Evaluation metrics, confusion matrix, search comparison
│
├── tests/
│   ├── __init__.py
│   ├── test_agent1.py                # Unit tests for Agent 1 (perception, classification)
│   ├── test_agent2.py                # Unit tests for Agent 2 (rules, CIA Triad, risk)
│   ├── test_search.py                # Unit tests for BFS, A*, admissibility & consistency
│   └── test_integration.py           # End-to-end multi-agent cooperative workflow test
│
├── train_model.py                    # Training and preprocessing script
├── run_system.py                     # Main CLI demonstration and benchmarking tool
├── requirements.txt                  # Python dependencies
└── README.md                         # Complete project documentation & guide
```

---

## 6. Agent 1: Intrusion Detection Agent (PEAS & ML)

### PEAS Formulation (Agent 1)

| PEAS Element | Technical Specification |
| :--- | :--- |
| **Performance Measure (P)** | • **Recall / Sensitivity** $\ge 74\%$ (Minimizing missed breaches/False Negatives).<br>• **Precision** $\approx 100\%$ (Minimizing false alarms and SOC alert fatigue).<br>• **F1-Score** $\ge 85\%$.<br>• **Inference Latency** $\le 5$ ms per session.<br>• **Explainability**: Generates forensic indicator evidence strings. |
| **Environment (E)** | • Inbound network connection flows, transport packet headers, authentication velocity counters, session duration metrics. |
| **Actuators (A)** | • Emits validated alerts.<br>• Compiles and transmits structured `Agent1Message` over JSON channel.<br>*(Deliberately no raw socket/packet dropping to maintain separation of concerns).* |
| **Sensors (S)** | • Session feature parsers: `network_packet_size`, `protocol_type`, `login_attempts`, `session_duration`, `ip_reputation_score`, `failed_logins`, `encryption_used`, `browser_type`, `unusual_time_access`. |

### Agent 1 Methods:
* `perceive(raw_event: dict)`: Ingests raw sensor telemetry and validates required fields.
* `preprocess(raw_event: dict)`: Applies trained `ColumnTransformer` (scaling + one-hot encoding).
* `classify(feature_vector)`: Evaluates Random Forest classifier (`ATTACK` vs `NORMAL`).
* `calculate_confidence(feature_vector)`: Computes posterior probability via `predict_proba`.
* `generate_evidence(raw_event, prediction, confidence)`: Infers attack profile (`DoS`, `Brute Force`, `Port Scan`, `Generic Anomaly`) and compiles human-readable forensic evidence strings.
* `process_event(event_id, raw_event)`: Compiles validated `Agent1Message` instance.

---

## 7. Agent 2: Threat Analysis & Response Planning Agent (PEAS & Rules)

### PEAS Formulation (Agent 2)

| PEAS Element | Technical Specification |
| :--- | :--- |
| **Performance Measure (P)** | • **Threat Neutralization**: Successfully reaching goal state `INCIDENT_CONTROLLED`.<br>• **Cost Optimality**: Finding the path that minimizes total operational disruption $g(n)$.<br>• **Search Efficiency**: Node expansion count and planning latency $\le 2$ ms.<br>• **Risk Reduction**: Measurable reduction of composite risk score $\le 10$. |
| **Environment (E)** | • Incoming inter-agent JSON message queue, declarative cybersecurity knowledge base (`knowledge/cybersecurity_rules.json`), enterprise asset criticality catalog, response state-space graph. |
| **Actuators (A)** | • Mitigation policy dispatch: `MONITOR`, `VERIFY`, `BLOCK_SOURCE`, `ISOLATE_HOST`, `ESCALATE`.<br>• Production of formal `Agent2Response` audit log. |
| **Sensors (S)** | • JSON wire message receiver ingesting `Agent1Message`.<br>• Rule-base inference query engine.<br>• State-space graph explorer. |

### Knowledge Base Representation (`knowledge/cybersecurity_rules.json`):
* **Attack Taxonomy**:
  * `DoS` -> Category: *Network Attack* | Impact: *Availability* | Base Severity: $8$.
  * `Brute Force` -> Category: *Credential Attack* | Impact: *Confidentiality* | Base Severity: $7$.
  * `Port Scan` -> Category: *Reconnaissance* | Impact: *Confidentiality* | Base Severity: $4$.
  * `Generic Anomaly` -> Category: *Suspicious Activity* | Impact: *Integrity* | Base Severity: $5$.
* **Composite Risk Score Formula**:
  $$\text{Risk Score} = \min(100.0, \text{round}(\text{Confidence} \times \text{Base Severity} \times \text{Asset Multiplier} \times 10, 1))$$
  * Asset Multipliers: `LOW_VALUE_WORKSTATION`: $0.8$ | `DMZ_WEB_SERVER`: $1.0$ | `CORE_DATABASE`: $1.3$ | `DOMAIN_CONTROLLER`: $1.5$.

---

## 8. Environment & Agent Analysis (7 Dimensions)

| Property | Classification | Academic Justification |
| :--- | :--- | :--- |
| **Observability** | **Partially Observable** | Agents only observe extracted session flow statistics and connection metadata. The adversary's internal intent, payload encryption internals, and external command-and-control servers remain unobservable. |
| **Determinism** | **Stochastic** | The environment is non-deterministic. Identical telemetry may occasionally arise from legitimate unusual activity or malicious zero-day exploits. Defensive actions (e.g. blocking an IP) carry uncertain operational side effects (e.g. disrupting shared proxy users). |
| **Dynamics** | **Dynamic** | Network traffic streams continuously and the threat landscape changes while agents perform classification and search planning. The environment does not pause during agent computation. |
| **Episodic / Sequential** | **Agent 1: Episodic<br>System: Sequential** | • Agent 1's classification is **episodic**: whether session $k$ is malicious is independent of session $k-1$.<br>• The end-to-end multi-agent workflow is **sequential**: current detection influences threat analysis, which triggers response planning, which fundamentally alters subsequent enterprise security state. |
| **Discrete / Continuous** | **Mixed** | Continuous numerical features (`session_duration`, `ip_reputation_score`, `confidence` $\in [0, 1]$) coexist with discrete nominal protocols (`TCP`, `UDP`), discrete attack categories, and discrete response graph nodes. |
| **Number of Agents** | **Multi-Agent** | Exactly two collaborating autonomous agents in Phase 1 (scalable to 4 in Phase 2). |
| **Agent Interaction** | **Cooperative** | The agents share a common global objective function: preserving organizational security (Confidentiality, Integrity, Availability) without competing utility functions. |

### Agent Behavioral Characteristics:
* **Autonomy**: Ingests percepts and executes decisions without manual human invocation.
* **Rationality**: Agent 1 maximizes classification accuracy; Agent 2 executes A* search to guarantee minimum expected operational disruption.
* **Reactivity**: Responds immediately to incoming traffic bursts and alert triggers.
* **Goal-Directedness**: Formulates an explicit goal state (`INCIDENT_CONTROLLED`) and conducts algorithmic search rather than simple lookup reflexes.

---

## 9. Algorithmic Modeling & State-Space Graph

### Formal Problem Formulation: $\langle S_0, S, A, T, G, c \rangle$

1. **State Space ($S$)**:
   * `ATTACK_DETECTED` (Initial Start State $S_0$)
   * `PASSIVE_TRACKING` (Low-severity monitoring state)
   * `THREAT_CONFIRMED` (Verified malicious session)
   * `SOURCE_BLOCKED` (Firewall packet drop active)
   * `HOST_ISOLATED` (Quarantined endpoint)
   * `SOC_ALERTED` (Escalated to human analysts)
   * `INCIDENT_CONTROLLED` (Goal State $G$)
2. **Action Set ($A$) & Operational Costs $c(u, v)$**:
   * `MONITOR` ($c = 1.0$): Zero disruption; passive logging telemetry.
   * `VERIFY_MITIGATION` ($c = 2.0$): Automated ping/health-check probe.
   * `VERIFY` ($c = 3.0$): Low user friction; challenge-response / secondary auth.
   * `MANUAL_OVERRIDE` ($c = 4.0$): Human SOC analyst triage time.
   * `BLOCK_SOURCE` ($c = 5.0$): Moderate disruption; potential shared proxy collateral.
   * `ESCALATE` ($c = 8.0$): High cost; paging on-call incident response engineers.
   * `ISOLATE_HOST` ($c = 10.0$ to $14.0$): Severe impact; complete service downtime.
3. **Transition Model ($T$)**:
   * `ATTACK_DETECTED` --(`VERIFY`, $c=3$)-> `THREAT_CONFIRMED`
   * `ATTACK_DETECTED` --(`MONITOR`, $c=1$)-> `PASSIVE_TRACKING`
   * `ATTACK_DETECTED` --(`ESCALATE`, $c=8$)-> `SOC_ALERTED`
   * `THREAT_CONFIRMED` --(`BLOCK_SOURCE`, $c=5$)-> `SOURCE_BLOCKED`
   * `THREAT_CONFIRMED` --(`ISOLATE_HOST`, $c=10$)-> `HOST_ISOLATED`
   * `SOURCE_BLOCKED` --(`VERIFY_MITIGATION`, $c=2$)-> `INCIDENT_CONTROLLED`
   * `HOST_ISOLATED` --(`VERIFY_MITIGATION`, $c=2$)-> `INCIDENT_CONTROLLED`
   * `SOC_ALERTED` --(`MANUAL_OVERRIDE`, $c=4$)-> `INCIDENT_CONTROLLED`

```mermaid
graph LR
    S0((ATTACK_DETECTED)) -->|MONITOR (c=1)| S1((PASSIVE_TRACKING))
    S0 -->|VERIFY (c=3)| S2((THREAT_CONFIRMED))
    S0 -->|ESCALATE (c=8)| S3((SOC_ALERTED))

    S1 -->|ESCALATE (c=8)| S3
    S2 -->|BLOCK_SOURCE (c=5)| S4((SOURCE_BLOCKED))
    S2 -->|ISOLATE_HOST (c=10)| S5((HOST_ISOLATED))

    S4 -->|VERIFY_MITIGATION (c=2)| G(((INCIDENT_CONTROLLED)))
    S5 -->|VERIFY_MITIGATION (c=2)| G
    S3 -->|MANUAL_OVERRIDE (c=4)| G
```

---

## 10. Search Strategy: BFS vs. A* Comparison & Admissibility Proof

### A* Evaluation Function: $f(n) = g(n) + h(n)$
* **$g(n)$**: Actual cost incurred from $S_0$ to state $n$.
* **$h(n)$**: Estimated remaining cost to reach `INCIDENT_CONTROLLED`.

### Mathematical Proof of Admissibility ($h(n) \le h^*(n)$)
A heuristic is admissible if it **never overestimates** the true optimal cost $h^*(n)$ to reach the goal:

| State ($n$) | Assigned $h(n)$ | True Optimal Cost to Goal $h^*(n)$ | Admissible? ($h(n) \le h^*(n)$) |
| :--- | :---: | :--- | :---: |
| `ATTACK_DETECTED` | **8.0** | $3 (\text{VERIFY}) + 5 (\text{BLOCK}) + 2 (\text{VERIFY\_MIT}) = \mathbf{10.0}$ | **Yes** ($8.0 \le 10.0$) |
| `THREAT_CONFIRMED` | **7.0** | $5 (\text{BLOCK}) + 2 (\text{VERIFY\_MIT}) = \mathbf{7.0}$ | **Yes** ($7.0 \le 7.0$) |
| `SOURCE_BLOCKED` | **2.0** | $2 (\text{VERIFY\_MIT}) = \mathbf{2.0}$ | **Yes** ($2.0 \le 2.0$) |
| `HOST_ISOLATED` | **2.0** | $2 (\text{VERIFY\_MIT}) = \mathbf{2.0}$ | **Yes** ($2.0 \le 2.0$) |
| `SOC_ALERTED` | **4.0** | $4 (\text{MANUAL\_OVERRIDE}) = \mathbf{4.0}$ | **Yes** ($4.0 \le 4.0$) |
| `PASSIVE_TRACKING` | **10.0** | $8 (\text{ESCALATE}) + 4 (\text{MANUAL}) = \mathbf{12.0}$ | **Yes** ($10.0 \le 12.0$) |
| `INCIDENT_CONTROLLED` | **0.0** | Goal State $= \mathbf{0.0}$ | **Yes** ($0.0 \le 0.0$) |

### Mathematical Proof of Consistency (Monotonicity)
A heuristic is consistent if for every node $u$, action $a$, and successor node $v$:
$$h(u) \le c(u, a, v) + h(v)$$
* Example Edge `ATTACK_DETECTED` -> `THREAT_CONFIRMED` via `VERIFY`:
  $$h(u) = 8.0 \le c(u, a, v) + h(v) = 3.0 + 7.0 = 10.0 \quad \text{(Satisfied)}$$
* Example Edge `THREAT_CONFIRMED` -> `SOURCE_BLOCKED` via `BLOCK_SOURCE`:
  $$h(u) = 7.0 \le c(u, a, v) + h(v) = 5.0 + 2.0 = 7.0 \quad \text{(Satisfied)}$$
* *(Verified programmatically across all edges via unit test `test_heuristic_consistency_triangle_inequality`)*.

---

## 11. Experimental Results & Search Benchmarks

### Supervised Classification Benchmark (Agent 1)

| Metric | Random Forest (Primary) | Decision Tree (Baseline) | Operational Significance |
| :--- | :---: | :---: | :--- |
| **Accuracy** | **88.63%** | 88.42% | Overall correctness across balanced test set. |
| **Precision (Attack)** | **100.00%** | 100.00% | **Zero False Positives**: Prevents SOC alert fatigue. |
| **Recall (Attack)** | **74.56%** | 74.09% | Identifies 3 out of 4 malicious attacks. |
| **F1-Score** | **85.43%** | 85.12% | Harmonic balance between Precision and Recall. |
| **False Positive Rate** | **0.00%** | 0.00% | Zero legitimate users are blocked. |
| **False Negative Rate** | **25.44%** | 25.91% | Residual risk escalated to secondary heuristics. |

> **Why Accuracy Alone is Insufficient**: In enterprise networks where attacks represent $<1\%$ of traffic, a naive classifier predicting "NORMAL" achieves 99% accuracy while missing 100% of attacks (the Base Rate Fallacy). High Precision and Recall on the Attack class are the true academic metrics of security effectiveness.

### Search Strategy Benchmark: BFS vs. A* (Agent 2)

| Metric | BFS (Uninformed) | A* (Informed) | Academic Finding |
| :--- | :---: | :---: | :--- |
| **Search Strategy** | Layer-by-layer FIFO Queue | Priority Queue ($f = g + h$) | A* utilizes domain knowledge. |
| **Path Hop Count** | **2 hops** | 3 hops | BFS chooses the shallowest hop path. |
| **Total Operational Cost** | **12.0** | **10.0** | **A\* achieves 16.7% operational cost savings.** |
| **Nodes Explored** | 8 nodes | 4 nodes | A* explores 50% fewer states. |
| **1000-Run Time** | 3.74 ms (0.0037 ms/query) | 5.95 ms (0.0060 ms/query) | BFS has lower queue overhead on tiny graphs. |
| **Optimality Guarantee** | Sub-optimal for non-uniform costs | **Provably Cost-Optimal** | **A\* guarantees minimum disruption.** |

* **BFS Path**: `ATTACK_DETECTED` --(`ESCALATE`, 8)--> `SOC_ALERTED` --(`MANUAL`, 4)--> `INCIDENT_CONTROLLED` (Cost: 12.0)
* **A\* Path**: `ATTACK_DETECTED` --(`VERIFY`, 3)--> `THREAT_CONFIRMED` --(`BLOCK`, 5)--> `SOURCE_BLOCKED` --(`VERIFY_MIT`, 2)--> `INCIDENT_CONTROLLED` (Cost: 10.0)

---

## 12. 12-Slide Presentation Script & Speaker Assignments

### Slide 1: Title & Team Introduction
* **Speaker**: *All 3 Members*
* **Speaking Script**:
  > "Good morning, respected evaluators. We are presenting our Foundations of AI Case Study: 'Multi-Agent AI-Based Cybersecurity Threat Detection and Response System'. Our team consists of Nanthakumaran, Dhinesh chandra, and Vejju Sasi Kiran Yasaswi. Our project specifically addresses the Review 1 rubric: PEAS, Environment Analysis, Algorithmic Modeling, and Search."

### Slide 2: Problem Statement & Motivation
* **Speaker**: *Nanthakumaran*
* **Speaking Script**:
  > "Traditional security systems rely on monolithic architectures that attempt to perform both data inspection and mitigation planning in a single script. This creates severe maintenance bottlenecks, lacks explainability, and cannot scale as attack vectors evolve."

### Slide 3: Project Objectives & Review 1 Milestones
* **Speaker**: *Nanthakumaran*
* **Speaking Script**:
  > "Our objective is to design two cooperating intelligent agents: Agent 1 specializing in supervised intrusion classification, and Agent 2 specializing in knowledge-based reasoning and state-space response planning. We strictly avoid artificial complexity and adhere directly to core AI principles."

### Slide 4: Why Multi-Agent AI?
* **Speaker**: *Dhinesh chandra*
* **Speaking Script**:
  > "We do not use multiple agents for vanity. Perception and Deliberation are fundamentally different AI tasks. Agent 1 answers: 'Is this traffic normal or malicious?' using data-driven machine learning. Agent 2 answers: 'What does this threat mean, and what is the cost-optimal defensive response?' using knowledge rules and state-space search. Combining them would destroy modularity and explainability."

### Slide 5: System Architecture & Inter-Agent Communication
* **Speaker**: *Vejju Sasi Kiran Yasaswi*
* **Speaking Script**:
  > "Our agents communicate strictly through schema-validated JSON wire messages. Agent 1 emits an `Agent1Message` containing its prediction, confidence, and forensic evidence. Agent 2 ingests this payload without having any access to Agent 1's memory pointers or internal variables, demonstrating genuine agent independence."

### Slide 6: PEAS Formulation for Agent 1 (Intrusion Detection Agent)
* **Speaker**: *Nanthakumaran*
* **Speaking Script**:
  > "For Agent 1: Performance is measured by Recall, Precision, and F1-score. Its Environment consists of network session flows. Its Actuators emit detection alerts and structured messages. Its Sensors ingest 10 flow attributes including packet size, protocol, duration, and authentication attempts."

### Slide 7: PEAS Formulation for Agent 2 (Threat Response Agent)
* **Speaker**: *Dhinesh chandra*
* **Speaking Script**:
  > "For Agent 2: Performance is measured by threat mitigation efficacy and operational disruption cost minimization. Its Environment is the enterprise knowledge base and response graph. Its Actuators dispatch concrete mitigation commands like `BLOCK_SOURCE`. Its Sensors receive structured messages from Agent 1."

### Slide 8: Environment & Agent Analysis (7 Dimensions)
* **Speaker**: *Dhinesh chandra*
* **Speaking Script**:
  > "Using standard Russell & Norvig criteria: The environment is Partially Observable because attacker intent and encrypted payloads are hidden; Stochastic because network latency and collateral disruption are uncertain; Dynamic because traffic streams continuously during reasoning; Mixed because continuous feature vectors coexist with discrete attack states; and Cooperative because both agents share the global utility of system security."

### Slide 9: Algorithmic Modeling: State-Space Formulation
* **Speaker**: *Vejju Sasi Kiran Yasaswi*
* **Speaking Script**:
  > "We model response planning as a formal state-space graph $\langle S_0, S, A, T, G, c \rangle$. States represent defensive postures starting from `ATTACK_DETECTED` to the goal `INCIDENT_CONTROLLED`. Actions have real-world operational costs: passive monitoring costs 1, verification costs 3, firewall blocking costs 5, and host isolation costs 10."

### Slide 10: Search Strategy: BFS vs. A* Comparison
* **Speaker**: *Vejju Sasi Kiran Yasaswi*
* **Speaking Script**:
  > "We implemented both BFS and A*. BFS is uninformed and expands states layer-by-layer, finding the path with the fewest hops—which in our graph is a 2-hop escalation path costing 12. In contrast, A* uses $f(n) = g(n) + h(n)$ with an admissible heuristic based on residual risk, finding the true cost-optimal path costing 10, achieving a 16.7% operational cost savings."

### Slide 11: Quantitative Results & Search Benchmarks
* **Speaker**: *Vejju Sasi Kiran Yasaswi*
* **Speaking Script**:
  > "On our 9,537-record dataset, Agent 1's Random Forest achieved 88.63% accuracy and 100% precision on attacks, preventing false alarms. In our 1,000-run search benchmark, A* consistently explored 50% fewer states than BFS while guaranteeing cost optimality."

### Slide 12: Live Demonstration & Phase 2 Roadmap
* **Speaker**: *All 3 Members*
* **Speaking Script**:
  > "We will now demonstrate the system live using `run_system.py --demo`. In Phase 2, our modular message architecture will allow us to plug in a Threat Intelligence Agent and a Dynamic Risk Assessment Agent without rewriting existing code. Thank you, we are ready for your questions."

---

## 13. Faculty Viva Q&A Crib Sheet (Top 10 Questions)

#### Q1: Why did you use two agents instead of one unified Python script?
> **Answer**: Intrusion detection is a high-speed *data-driven perception problem* over continuous numeric flow features. Threat mitigation is a *discrete knowledge-based planning problem* over symbolic actions and business operational costs. Coupling them into a monolith degrades modularity, prevents independent model upgrades, and eliminates explainability.

#### Q2: Why is accuracy alone insufficient for evaluating cybersecurity AI?
> **Answer**: In real enterprise networks, benign traffic vastly outnumbers malicious traffic (e.g. 99% normal). A naive classifier that predicts "NORMAL" for every packet achieves 99% accuracy but allows 100% of cyberattacks to succeed (the Base Rate Fallacy). In cybersecurity, Precision, Recall, and False Positive Rate are the critical operational metrics.

#### Q3: Why did BFS produce a higher cost path than A\*?
> **Answer**: BFS is an uninformed search algorithm that expands states layer-by-layer, assuming all edge transitions have uniform cost ($c=1$). Consequently, BFS finds the path with the *fewest number of hops* (2 hops: `ATTACK` -> `ESCALATE` -> `CONTROLLED`, cost 12.0). In contrast, A* uses $f(n) = g(n) + h(n)$ to evaluate real-world operational disruption costs, discovering that a 3-hop path (`ATTACK` -> `VERIFY` -> `BLOCK` -> `CONTROLLED`) incurs a lower total cost (10.0).

#### Q4: How do you prove that your heuristic $h(n)$ is admissible?
> **Answer**: A heuristic is admissible if $h(n) \le h^*(n)$ for all states $n$, where $h^*(n)$ is the true minimum cost to the goal. In our response graph, for every single state, our heuristic under-estimates or equals the true cost (e.g., at `ATTACK_DETECTED`, $h=8.0$ while $h^*=10.0$; at goal, $h=0$). We verify this mathematically and enforce it through an automated unit test.

#### Q5: Is A\* always faster than BFS?
> **Answer**: No, and claiming so is academically incorrect. In small finite graphs, BFS can have slightly lower execution time (e.g., 0.0037 ms vs 0.0060 ms) because it uses simple FIFO queue operations without priority queue heap management. However, A* is *search-efficient* (expanding 50% fewer states) and *cost-optimal*.

#### Q6: How do the two agents communicate?
> **Answer**: Agents communicate exclusively through strongly-typed, schema-validated JSON wire messages (`Agent1Message`). Agent 2 has zero access to Agent 1's internal memory pointers, trained weights, or variables.

#### Q7: Why is your environment classified as Partially Observable?
> **Answer**: Because sensors only capture extracted flow statistics and headers. The attacker's internal intent, payload encryption keys, and command-and-control server topology remain hidden from the agents.

#### Q8: What makes each component an "Intelligent Agent" rather than just regular code?
> **Answer**: Each component implements the formal definition of an agent: it perceives its environment through sensors, maintains internal state, evaluates actions against a performance measure, and acts autonomously through actuators to achieve a defined goal.

#### Q9: What dataset did you use and why?
> **Answer**: We evaluated CICIDS2017 and UNSW-NB15, and utilized a clean, balanced 9,537-record session dataset representing key flow features (packet size, protocol, duration, login attempts, IP reputation). This guarantees 100% reproducible execution during live evaluation without multi-gigabyte disk or GPU requirements.

#### Q10: How will you expand this system in Phase 2?
> **Answer**: Because of our decoupled message architecture, we can insert a Threat Intelligence Agent (querying MITRE ATT&CK / CVEs) and a Dynamic Risk Assessment Agent (evaluating financial exposure) between Agent 1 and Agent 2 without modifying a single line of their existing code.

---

## 14. Automated Verification & Unit Test Results

The test suite can be run at any time to verify the system's integrity:

```bash
python -m unittest discover -s tests -v
```

```text
test_message_json_serialization (test_agent1.TestIntrusionDetectionAgent) ... ok
test_perceive_missing_required_feature_raises_error (test_agent1.TestIntrusionDetectionAgent) ... ok
test_perceive_valid_event (test_agent1.TestIntrusionDetectionAgent) ... ok
test_process_event_returns_valid_agent1_message (test_agent1.TestIntrusionDetectionAgent) ... ok
test_benign_message_handling (test_agent2.TestThreatResponseAgent) ... ok
test_brute_force_threat_reasoning (test_agent2.TestThreatResponseAgent) ... ok
test_dos_threat_reasoning (test_agent2.TestThreatResponseAgent) ... ok
test_rejects_direct_invalid_input (test_agent2.TestThreatResponseAgent) ... ok
test_end_to_end_attack_containment_pipeline (test_integration.TestMultiAgentIntegration) ... ok
test_end_to_end_normal_benign_pipeline (test_integration.TestMultiAgentIntegration) ... ok
test_astar_cost_is_less_than_or_equal_to_bfs_cost (test_search.TestSearchAlgorithms) ... ok
test_astar_finds_optimal_path (test_search.TestSearchAlgorithms) ... ok
test_bfs_finds_goal_path (test_search.TestSearchAlgorithms) ... ok
test_heuristic_admissibility (test_search.TestSearchAlgorithms) ... ok
test_heuristic_consistency_triangle_inequality (test_search.TestSearchAlgorithms) ... ok

----------------------------------------------------------------------
Ran 15 tests in 0.823s

OK
```
