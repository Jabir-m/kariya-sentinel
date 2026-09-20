# KARIYA AI Operational Skills & Capabilities Registry

This document specifies the operational capabilities, tools, and workflows of KARIYA AI for the ICSC 2026 Universities Hackathon (Track D).

---

## 1. Autonomous Incident Triage & Scoring (Track D Core)
Automated categorization, severity assignment, and SLA enforcement for incoming reports.
- **Incident Categorization**: Aligns raw reports with 7 standardized threat categories (Ransomware, Account Takeover, Phishing, BEC, Defacement, Data Leak, DoS).
- **Urgency Scoring**: Ranks threats by asset criticality (P1 Critical: 15-min SLA; P2 High: 1-hr SLA; P3 Medium: 4-hr SLA; P4 Low: 24-hr SLA).

---

## 2. Technical IOC Harvesting & Enrichment
Extracts structured indicators from messy or defanged incident descriptions:
- IPv4 addresses (`1.2.3.4`, `1[.]2[.]3[.]4`).
- Domains & URLs (`.ng`, `.gov.ng`, `.onion`, `.top`, `.online`).
- Hashes (MD5, SHA1, SHA256) and CVE references.

---

## 3. Nigerian PII Sanitization & Redaction
Protects citizen privacy and enforces Nigeria Data Protection Act (NDPA/NDPR) compliance before sharing incident data:
- Nigerian Phone Numbers (`0803...`, `+234...`) -> `[REDACTED_PHONE]`.
- Bank Verification Numbers (`22...`) -> `[REDACTED_BVN]`.
- National Identity Numbers (`54...`) -> `[REDACTED_NIN]`.
- NUBAN Bank Account Numbers -> `[REDACTED_ACCOUNT]`.
- Civil Servant Names & Victim Emails -> `[REDACTED_OFFICER_NAME]`, `[REDACTED_EMAIL]`.

---

## 4. Multi-Agency Deduplication & Correlation
Groups disparate reports describing the same underlying cyber incident into a unified Master Incident:
- Reduces notification noise by up to 95%.
- Matches identical threat IOCs and computes cosine semantic similarity.

---

## 5. Offline Resilience & Outage Handling (Rule 06)
Maintains 100% operational uptime during municipal power and internet blackouts:
- Queues incoming messages into a local transactional SQLite store (`triage_offline.db`).
- Runs local NLP pipelines with zero cloud latency.
- Auto-syncs to national coordination centers (ngCERT/NITDA) once network returns.

---

## 6. System Execution & Research Tools
- **`terminal` MCP**: Bash command execution (`execute_command`) and host vitals (`get_system_info`).
- **`websearch` MCP**: Anonymous DuckDuckGo web search, news search, and URL text fetch.
- **`filesystem` MCP**: Structured workspace file inspection, edits, and directory tree management.
- **`memory` MCP**: Persistent knowledge graph entity management.
