# Mermaid Figures for SkillChain-Logistics / FreightSkillBench

Use these Mermaid diagrams in the manuscript, slides, or as source for rendered vector figures.

---

# Figure 1. SkillChain-Logistics Threat Model

```mermaid
flowchart LR
    A[Third-party agent skill package<br/>SKILL.md / tool instructions] --> B[AI logistics extraction agent]
    C[Untrusted logistics documents<br/>Email / PDF-text / EDI] --> B

    B --> D[Proposed logistics transaction JSON]
    D --> E[Mock or production TMS/API]

    E --> F[Load creation]
    E --> G[Carrier assignment]
    E --> H[Dispatch instruction]
    E --> I[Appointment scheduling]
    E --> J[Shipment status update]
    E --> K[Invoice or payee action]

    F --> L[Transportation operation]
    G --> L
    H --> L
    I --> L
    J --> L
    K --> L

    L --> M[Dependent-sector exposure<br/>Energy / Healthcare / Food / Manufacturing]

    X[Skill or document manipulation] -.-> B
    X -.-> D
    X -.-> E

    classDef risk fill:#ffe6e6,stroke:#cc0000,stroke-width:1px;
    class X,D,E risk;
```

Recommended caption:

**Figure 1. SkillChain-Logistics threat model.** Third-party agent skills and untrusted logistics documents create a cyber/logical dependency between the AI extraction layer and transportation-sector transaction systems.

---

# Figure 2. FreightSkillBench Benchmark Pipeline

```mermaid
flowchart TD
    A[Canonical synthetic shipment<br/>ground truth] --> B[Clean document renderings]
    B --> B1[Email]
    B --> B2[PDF-like text]
    B --> B3[EDI 204 / 210 / 214]

    A --> C[Adversarial mutation generator]
    B1 --> C
    B2 --> C
    B3 --> C

    C --> D[Adversarial document set]
    D --> E[Model / agent extraction]
    E --> F[Extracted transaction JSON]
    F --> G[D0-D5 defense evaluator]
    G --> H[Mock TMS/API audit log]
    H --> I[Rule-based unsafe adjudication]
    I --> J[Metrics by model, defense,<br/>attack type, and document type]
```

Recommended caption:

**Figure 2. FreightSkillBench benchmark pipeline.** Canonical transactions are rendered into logistics document formats, mutated into adversarial variants, processed by model/agent extractors, and evaluated through defense controls and rule-based adjudication.

---

# Figure 3. D0-D5 Defense Stack

```mermaid
flowchart LR
    T[Proposed transaction] --> D0[D0<br/>No control]
    T --> D1[D1<br/>Schema validation]
    T --> D2[D2<br/>Field-level validation]
    T --> D3[D3<br/>Capability manifest]
    T --> D4[D4<br/>Approval gate]
    T --> D5[D5<br/>Full control]

    D0 --> R0[Accept / execute]
    D1 --> R1[Block malformed only]
    D2 --> R2[Block high-risk field divergence]
    D3 --> R3[Block undeclared capabilities only]
    D4 --> R4[Escalate high-risk actions]
    D5 --> R5[Validate fields + enforce capabilities + gate approvals]

    classDef weak fill:#fff4cc,stroke:#c09000,stroke-width:1px;
    classDef strong fill:#e6ffe6,stroke:#008000,stroke-width:1px;
    class D0,D1,D3 weak;
    class D2,D4,D5 strong;
```

Recommended caption:

**Figure 3. Defense-control conditions.** The evaluation compares no control, schema-only, field-level validation, manifest-only, approval-gated, and full-control settings.

---

# Figure 4. Attack Taxonomy

```mermaid
mindmap
  root((FreightSkillBench Attacks))
    Hazmat suppression
      Hazmat flag
      Hazmat class
      UN number
      Safety compliance
    Appointment sabotage
      Appointment start
      Appointment end
      Facility capacity
      Receiving delay
    Dispatch poisoning
      Facility ID
      Dock
      City and ZIP
      Wrong-site dispatch
    Carrier substitution
      Carrier name
      DOT number
      MC number
      Chain of custody
    Status concealment
      Tracking status
      Exception status
      Delayed escalation
```

Recommended caption:

**Figure 4. FreightSkillBench logistics attack taxonomy.** The benchmark targets high-risk logistics fields that connect document interpretation to transportation operations.

---

# Figure 5. Cyber/Logical Interdependency Framing

```mermaid
flowchart LR
    A[Agent-skill ecosystem] -->|instruction dependency| B[AI-enabled logistics workflow]
    C[External document stream] -->|untrusted input dependency| B
    B -->|transaction dependency| D[TMS / dispatch / appointment systems]
    D -->|operational dependency| E[Transportation movement]
    E -->|supply dependency| F[Dependent sectors]

    F --> F1[Energy]
    F --> F2[Healthcare]
    F --> F3[Food and agriculture]
    F --> F4[Critical manufacturing]

    classDef dep fill:#eef5ff,stroke:#3366cc,stroke-width:1px;
    class A,B,C,D,E,F dep;
```

Recommended caption:

**Figure 5. Cyber/logical interdependency framing.** The agent-skill layer becomes an upstream dependency for AI-enabled logistics workflows that can propagate unsafe transaction states into transportation operations and dependent-sector supply continuity.

---

# Figure 6. Results Interpretation Logic

```mermaid
flowchart TD
    A[Live model output] --> B{Unsafe under D0?}
    B -->|No| C[Model resisted or failed attack]
    B -->|Yes| D{Unsafe under D3 manifest only?}
    D -->|Yes| E[Capability manifest insufficient]
    D -->|No| F[Capability restriction helped]
    E --> G{Blocked under D2/D5?}
    G -->|Yes| H[Field-level logistics validation effective]
    G -->|No| I[Control gap remains]
```

Recommended caption:

**Figure 6. Results interpretation logic.** Unsafe outcomes under D0 and D3, combined with blocking under D2 and D5, indicate that field-level logistics validation is necessary beyond capability manifests.
```
