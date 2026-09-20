# Autonomous Heartbeat Routine (HEARTBEAT.md)

Standing autonomous inspection instructions for KARIYA AI during periodic and scheduled self-audits.

---

## Standing Inspection Checklist

1. **Incident Triage Queue Health**:
   - Check if any P1 Critical incidents (e.g. active Ransomware or IPPIS Account Takeovers) have been pending triage without action.
   - Verify that the urgent-first sorting order is preserved.

2. **Offline Buffer & Sync Status (Rule 06)**:
   - Inspect `triage_offline.db` for queued reports.
   - If network connectivity is active and queued reports exist, trigger `sync_offline_queue()`.

3. **Subsystem & Host Health**:
   - Query `get_system_info` for disk space, CPU load, and memory headroom.
   - Verify active connectivity to MCP servers (`terminal`, `websearch`, `filesystem`, `memory`, `everything`, `sequentialthinking`).

4. **Workspace & Model Integrity**:
   - Verify integrity of `dataset.json`, `main.py`, `templates/index.html`, and `kariya/pipeline.py`.

---

## Output Protocol
- **When all queues and systems are clear**:
  Return `HEARTBEAT_OK` with summary of active master incidents, offline sync state, and disk space.
- **When SLA is in breach or critical threat is unhandled**:
  Return `HEARTBEAT_ALERT` detailing the urgent incident ID and required SOC action.
