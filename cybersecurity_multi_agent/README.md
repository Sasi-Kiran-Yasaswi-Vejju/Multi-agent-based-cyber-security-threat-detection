# Multi-Agent AI-Based Cybersecurity Threat Detection and Response System

**Course**: 23CSE401 – Foundations of Artificial Intelligence  
**Institution**: Amrita Vishwa Vidyapeetham  
**Architecture**: 4-Agent Autonomous Multi-Agent AI System  

---

## Team Members & Responsibilities

| Student Name | Roll Number | Primary Agent / Role | Core Academic Responsibilities |
| :--- | :--- | :--- | :--- |
| **Nanthakumaran** | `CB.SC.U4CSE23341` | **Agent 1: Intrusion Detection** | Data Perception, Feature Normalization, Supervised Random Forest Classifier, Confidence Scoring, PEAS |
| **Dhinesh chandra** | `CB.SC.U4CSE23310` | **Agent 2: Threat Analysis** | Symbolic Threat Attribution, IoC Extraction, Query Term Synthesis, Backward Clarification Handling |
| **Vejju Sasi Kiran Yasaswi** | `CB.SC.U4CSE23356` | **Agent 3: Threat Intelligence & Agent 4: Risk & Response** | MITRE ATT&CK STIX Graph (NetworkX), CISA KEV Engine, Hybrid Search (Keyword + Semantic + BFS), Multi-factor Risk Scoring, A* Defensive Planning, Central Orchestration |

---

## 1. Executive Architecture & Core Principles

This system moves beyond monolithic models and simple function chains by implementing **four specialized, autonomous AI agents** governed by a central coordinator with shared incident state, smart routing, and backward communication.

```
                    SECURITY EVENT TELEMETRY
                               │
                               ▼
                   +───────────────────────+
                   │        Agent 1        │
                   │   DETECT (ML Reflex)  │
                   +───────────┬───────────+
                               │
                      Is it Benign & Conf >= 0.80?
                       /                       \
                     YES                        NO
                     │                           │
          [SMART ROUTING: EARLY EXIT]            ▼
          Prune downstream agents       +───────────────────────+
          Log & Pass (Saved 3 calls)    │        Agent 2        │
                                        │    ANALYZE (Threat)   │
                                        +───────────┬───────────+
                                                    │
                                           INTELLIGENCE_REQUEST
                                                    │
                                                    ▼
                                        +───────────────────────+
                                        │        Agent 3        │
                                        │    ENRICH (Intel)     │
                                        +───────────┬───────────+
                                                    │
                                           INTELLIGENCE_RESPONSE
                                                    │
                                                    ▼
                                        +───────────────────────+
                                        │        Agent 4        │
                                        │  ASSESS + PLAN (Risk) │
                                        +───────────┬───────────+
                                                    │
                                        Missing Asset Context?
                                         /                 \
                                       YES                  NO
                                       │                     │
                             CLARIFICATION_REQUEST           ▼
                               (Agent 4 -> Agent 2)    FINAL_DECISION
                                       │               (A* Optimal Path)
                             CLARIFICATION_RESPONSE
                               (Agent 2 -> Agent 4)
                                       │
                                       ▼
                                 Recalculate &
                                 Emit FINAL_DECISION
```

---

## 2. Quick Start: How to Run the Project

Navigate to the project directory in PowerShell or Terminal:
```bash
cd "c:/Users/sasik/Downloads/FOAI/Case Study/cybersecurity_multi_agent"
```

### Execution Commands

#### 1. Live 4-Agent Demonstration CLI
```bash
python run_system.py
```
* **Scenario 1**: Credential Brute Force on Core Database $\to$ full 4-agent containment workflow.
* **Scenario 2**: Weaponized Volumetric DoS targeting CISA KEV `CVE-2026-88779` $\to$ CISA KEV priority escalation to `CRITICAL` with mandated remediation directives.
* **Scenario 3**: Legitimate User Session $\to$ Smart routing prunes downstream agents at Agent 1, saving 3 unnecessary agent calls.
* **Scenario 4**: Intrusion with missing asset context $\to$ Agent 4 triggers backward `CLARIFICATION_REQUEST` to Agent 2, which responds with verified context.

#### 2. Algorithmic Search Benchmark (BFS vs. A*)
```bash
python run_system.py --benchmark
```
* Runs 1,000 iterations comparing uninformed Breadth-First Search (BFS) against informed A\* search.
* Proves that A\* finds the **cost-optimal mitigation path (Cost: 10.0 vs BFS Cost: 12.0)** with **50% fewer node expansions** and **16.7% operational cost savings**.

#### 3. Run the Complete Automated Test Suite (43 Tests)
```bash
python -u -m unittest discover -s tests -v
```
* Runs all 43 unit, search, collaboration, and end-to-end tests with **100% pass rate**.

#### 4. Model Training & Evaluation
```bash
python train_model.py
```

---

## 3. Formal PEAS Profiles for All Four Agents

| Agent | Performance (P) | Environment (E) | Actuators (A) | Sensors (S) |
| :--- | :--- | :--- | :--- | :--- |
| **Agent 1: Intrusion Detection** | Accuracy, Recall (Attack), F1-Score, False Positive Rate (FPR $\le 0.05$) | Raw network packet flows & session connection telemetry | Security alert envelopes (`ALERT`), feature summaries, confidence metrics | Network flow features (packet size, protocol, failed logins, duration) |
| **Agent 2: Threat Analysis** | Attribution accuracy, indicator quality, query relevance, clarification latency | Security alerts from Agent 1 and enterprise asset inventory | Intelligence queries (`INTELLIGENCE_REQUEST`), clarification responses | Structured `ALERT` messages and raw feature summaries |
| **Agent 3: Threat Intelligence** | Retrieval Precision@K, MRR, Graph path consistency, CVE accuracy | MITRE ATT&CK STIX 2.0 knowledge graph & CISA KEV catalog | Intelligence dossiers (`INTELLIGENCE_RESPONSE`), clarification requests | Structured `INTELLIGENCE_REQUEST` queries from Agent 2 |
| **Agent 4: Risk & Response Planning** | Risk calibration accuracy, mitigation cost optimality, operational disruption | Consolidated multi-agent incident dossiers | Mitigation plans (`FINAL_DECISION`), backward clarification requests | Consolidated `INTELLIGENCE_RESPONSE` dossiers from Agent 3 |

---

## 4. Datasets & Knowledge Representation

### 1. `enterprise-attack.json` (MITRE ATT&CK STIX 2.0)
* **Size**: 51.3 MB | **Objects**: 26,086 STIX objects.
* **Graph Structure**: Modeled as a **NetworkX DiGraph** $G = (V, E)$ containing **2,510 active nodes** and **43,950 directed edges**.
* **Entity Classes**: Techniques & Sub-techniques (858), Tactics (15), Threat Groups / Intrusion Sets (191), Software/Malware/Tools (828), Defensive Mitigations (268).
* **Relationships Traversed**: `uses`, `mitigates`, `subtechnique-of`, and reverse navigational edges.

### 2. `known_exploited_vulnerabilities.json` (CISA KEV)
* **Size**: 1.7 MB | **Count**: 1,734 actively exploited CVEs tracked by CISA.
* **Indexed Schema**: `cveID`, `vendorProject`, `product`, `vulnerabilityName`, `dateAdded`, `shortDescription`, `requiredAction`, `knownRansomwareCampaignUse` (361 associated with active ransomware), `cwes`.

### 3. `cybersecurity_intrusion_data.csv`
* **Size**: 725 KB | **Count**: 9,537 session records.
* **Features**: `network_packet_size`, `protocol_type`, `login_attempts`, `session_duration`, `encryption_used`, `ip_reputation_score`, `failed_logins`, `browser_type`, `unusual_time_access`, `attack_detected`.
* **Class Distribution**: 55.3% Normal (5,273) vs 44.7% Attack (4,264).

### 4. `MachineLearningCVE/` (CIC-IDS2017)
* **Size**: 939.6 MB across 8 PCAP ISCX CSV files | **Total Records**: 2,830,743 network flows with 79 features.
* **Attack Profiles**: DoS Hulk, DDoS, PortScan, FTP-Patator, SSH-Patator, Botnet, Web Attacks (SQLi/XSS), Infiltration, Heartbleed.

---

## 5. Search Algorithms Implemented

### 1. Breadth-First Search (BFS) — Uninformed Baseline (Agent 3 & Benchmarks)
* **In Agent 3**: Traverses the MITRE ATT&CK knowledge graph starting from the top-scoring technique node to depth $d=2$, discovering associated tactics, threat groups (e.g., APT28, Lazarus), malware, and mitigations.
* **Complexity**: Time $O(b^d)$, Space $O(b^d)$ where $b$ is the branching factor.

### 2. Semantic Search (Cosine Similarity) — Agent 3
* **Implementation**: TF-IDF vector space with character n-grams and English stop-word removal.
* **Formula**:
  $$\text{sim}(q, d) = \frac{\vec{q} \cdot \vec{d}}{\|\vec{q}\| \|\vec{d}\|}$$
* **Role**: Matches natural-language threat descriptions and IoC strings against 697 ATT&CK technique descriptions.

### 3. A* Search — Informed Cost-Optimal Planning (Agent 4)
* **State Space**: Response graph representing defensive containment postures (`ATTACK_DETECTED`, `PASSIVE_TRACKING`, `THREAT_CONFIRMED`, `SOURCE_BLOCKED`, `HOST_ISOLATED`, `INCIDENT_CONTROLLED`).
* **Evaluation Function**:
  $$f(n) = g(n) + h(n)$$
  * $g(n)$: Accumulated operational disruption cost from start state to node $n$.
  * $h(n)$: Estimated remaining operational friction to reach `INCIDENT_CONTROLLED`.
* **Admissibility & Consistency**: The heuristic is provably admissible ($h(n) \le h^*(n)$) and consistent ($h(u) \le c(u, a, v) + h(v)$), guaranteeing that A\* returns a provably cost-optimal solution.

---

## 6. Deterministic Multi-Factor Risk Model (Agent 4)

Agent 4 computes risk deterministically without allowing LLMs to fabricate numerical scores:
$$\text{Risk Score} = 0.25 \times \text{Severity} + 0.20 \times \text{Asset} + 0.20 \times \text{Exploitability} + 0.15 \times \text{Impact} + 0.10 \times \text{Exposure} + 0.10 \times \text{Confidence}$$

* **Threat Severity** (0–100): Derived from Agent 2 base severity ($0\text{--}10 \times 10$).
* **Asset Criticality** (0–100): Derived from asset tier (`LOW_VALUE_WORKSTATION`: 40, `DMZ_WEB_SERVER`: 66.7, `CORE_DATABASE`: 86.7, `DOMAIN_CONTROLLER`: 100).
* **Exploitability** (0–100): Elevates to 95–100 if confirmed in CISA KEV or associated with active ransomware.
* **CIA Impact** (0–100): Weighted by CIA property (Confidentiality: 85, Integrity: 80, Availability: 75).
* **Network Exposure** (0–100): Perimeter DMZ (90) vs Internal Subnet (40).
* **Detection Confidence** (0–100): Posterior model confidence from Agent 1 and Agent 3.

**Risk Tiers**:
* `0 – 24.9`: **LOW**
* `25 – 49.9`: **MEDIUM**
* `50 – 74.9`: **HIGH**
* `75 – 100.0`: **CRITICAL**

---

## 7. Automated Test Suite (43 Tests)

The test suite covers every layer of the architecture:
* **`tests/test_agent1.py`** (4 tests): Ingestion validation, missing value imputation, Random Forest prediction, confidence calculation.
* **`tests/test_agent2.py`** (4 tests): Message deserialization, taxonomy rule matching, IoC extraction, CIA Triad mapping.
* **`tests/test_agent3.py`** (6 tests): Keyword search, TF-IDF semantic cosine search, BFS graph expansion over MITRE ATT&CK, CISA KEV known/unknown CVE lookups, `INTELLIGENCE_RESPONSE` synthesis.
* **`tests/test_agent4.py`** (5 tests): Deterministic risk calculation across all 4 tiers, A\* search path cost optimality, backward clarification on unknown asset context, CISA KEV risk elevation.
* **`tests/test_search.py`** (5 tests): Response graph modeling, A\* heuristic admissibility, consistency triangle inequality, BFS vs A\* comparison.
* **`tests/test_integration.py`** (2 tests): End-to-end serialized JSON wire transmission across agents.
* **`tests/test_collaboration.py`** (5 tests): Full 4-agent collaborative containment, smart routing benign early exit (3 calls saved), backward clarification cycle, CISA KEV priority escalation, message auditability.
* **`tests/test_end_to_end.py`** (12 tests): All 12 required incident scenarios (Benign, Brute Force, Port Scan, DoS, Web Attack, Botnet, Generic Anomaly, CISA KEV Exploit, Disagreements, Missing Asset Context, Borderline Detection, Critical Attack).

---

## 8. Viva Defense: Top Questions & Answers

### Q1: Why is this a Multi-Agent System rather than 4 Python functions or 4 LLM prompts?
**Answer**: Each agent is an autonomous specialist operating with distinct PEAS formulations, specialized environments, and distinct AI sub-disciplines:
* Agent 1 is a **data-driven machine learning reflex agent** operating on telemetry feature vectors.
* Agent 2 is a **symbolic reasoning agent** operating on attack taxonomies and IoCs.
* Agent 3 is a **knowledge representation and graph traversal agent** operating on 26,000+ STIX entities and CISA KEV catalogs.
* Agent 4 is an **informed search and decision agent** operating on state-space action graphs via A\*.
The agents communicate through strongly typed JSON messages, support backward clarification dialogues, and are coordinated by an orchestrator with smart routing.

### Q2: How does the system handle high-confidence benign traffic?
**Answer**: Through **Smart Routing**. If Agent 1 classifies an event as `NORMAL` with confidence $\ge 0.80$, the orchestrator immediately sets the status to `CLOSED_BENIGN` and terminates the pipeline. This avoids invoking Agents 2, 3, and 4, eliminating alert fatigue and reducing unnecessary computational overhead.

### Q3: Why is A* used instead of BFS for response planning?
**Answer**: Defensive cybersecurity actions have non-uniform operational costs. A naive BFS treats all actions as unit-cost ($c=1$) and finds the shallowest path (2 hops, e.g., immediately alerting the SOC, Cost = 12.0). A\* uses an admissible heuristic $h(n)$ to account for real operational costs and service disruption, discovering the 3-hop path (`BLOCK_SOURCE_IP`, Cost = 10.0), achieving a **16.7% operational cost savings**.

### Q4: What prevents infinite communication loops when agents request clarification?
**Answer**: The central orchestrator tracks conversation IDs, message IDs, and enforces a strict `max_iterations = 6` bound along with state transition checks.
