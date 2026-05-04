# Velociraptor → Splunk Pipeline Setup

This pipeline replaces the old "Splunk UF on the victim" approach with a more realistic DFIR workflow:

> Analyst runs a Velociraptor artifact → Velociraptor server forwards the results to Splunk via HTTP Event Collector (HEC) → Analyst hunts what they collected.

Why this is better for training:

- Mirrors real-world tier-2/3 DFIR work where you target collections deliberately
- Forces analysts to understand which artifacts are useful for which investigations
- Removes the "everything is already in Splunk, just search" crutch
- Single ingestion pipeline regardless of whether the victim has Sysmon, Security log auditing, etc.

There are two ways to wire this up — pick one based on how Velociraptor is licenced in your environment.

---

## Option A: Server-side `Generic.Forensic.SplunkUpload` artifact (recommended)

This is the cleanest option. Velociraptor's built-in `Generic.Forensic.SplunkUpload` artifact ships any other artifact's results to a Splunk HEC endpoint. You configure it once and from then on every collection automatically lands in Splunk.

### Step 1 — Configure HEC on Splunk

In the Splunk web UI:

1. **Settings → Data inputs → HTTP Event Collector**
2. **Global Settings** (top right) → **All Tokens** = Enabled, **Default Source Type** = `_json`, **Default Index** = `velociraptor`. Save.
3. Verify **port 8088** is in the listed ports. (Default is 8088.) If your Splunk runs in Docker, expose this port — see the docker-compose update below.

Then create the index and the token:

4. **Settings → Indexes → New Index** → name `velociraptor`, type `Events`. Save.
5. **Settings → Data inputs → HTTP Event Collector → New Token**:
   - **Name**: `velociraptor`
   - **Source name override**: `velociraptor`
   - **Description**: `Velociraptor artifact uploads`
   - **Output Group**: leave default
   - **Source type**: `_json`
   - **Allowed indexes**: `velociraptor`
   - **Default index**: `velociraptor`
   - Click **Submit**

6. **Copy the token value** that's displayed — you need it in Step 3.

### Step 2 — Update docker-compose to expose HEC port

The default `setup/docker-compose.yml` doesn't publish 8088. Edit it:

```yaml
services:
  splunk:
    image: splunk/splunk:9.3
    container_name: bttrainer-splunk
    ports:
      - "8100:8000"
      - "8189:8089"
      - "9997:9997"
      - "8088:8088"   # <-- ADD THIS LINE for HEC
```

Then restart the stack:

```bash
cd setup/
docker compose up -d
```

### Step 3 — Configure Velociraptor to use the HEC token

In the Velociraptor GUI:

1. **Server Artifacts** (left sidebar) → search for `Generic.Forensic.SplunkUpload`
2. Click it, then **Configure**
3. Fill in:
   - **URL**: `http://<your-splunk-host-ip>:8088/services/collector/event`
   - **Token**: the token you copied from Splunk
   - **Index**: `velociraptor`
   - **Verify_SSL**: false (lab only)
4. **Launch** the artifact once against your server to verify it accepts the config

### Step 4 — Wrap your collections

When running an artifact in Velociraptor and you want it to land in Splunk, you have two patterns:

**Pattern A — Post-process every hunt:** Use the **Post Process** tab in the hunt creation dialog and add `Generic.Forensic.SplunkUpload`. Every artifact collected in that hunt automatically forwards.

**Pattern B — Server-side daemon (one-time setup):** In Velociraptor, create a server-side event-monitoring rule that watches for new collections and auto-forwards them. Server-Side Artifacts → `Server.Monitor.Health.Splunk` (or write your own VQL rule). More complex but fully hands-off after setup.

**For training purposes, Pattern A is right** — analysts deliberately add the post-process step, which makes the "what am I shipping to Splunk?" question explicit.

### Step 5 — Verify end-to-end

1. From the trainer, detonate **T1082-1** (`systeminfo` enumeration)
2. In Velociraptor, run `Windows.System.Pslist` against your victim, with `Generic.Forensic.SplunkUpload` as a post-process step
3. In Splunk, search:
   ```
   index=velociraptor
   ```
4. You should see the pslist output as JSON events. Filter further with:
   ```
   index=velociraptor sourcetype=_json | spath "Name"
   ```

If nothing shows up, see Troubleshooting at the bottom of this doc.

---

## Option B: Manual export + Splunk one-shot ingest

If you can't use HEC for some reason (locked-down Splunk, no network path between Velociraptor and Splunk, etc.), the analyst-driven manual flow is:

1. Run the artifact in Velociraptor
2. Download the result as JSON or CSV from the GUI
3. Upload it via Splunk's **Settings → Add Data → Upload** flow
4. Search in Splunk

This is more tedious but works in the most restrictive environments. It's actually quite educational for analysts because they have to *handle the evidence* rather than just searching it. Worth using occasionally even if Option A is set up, just to keep the muscle memory.

---

## Updated hunt pack queries

Once the pipeline is in place, the hunt pack queries in the trainer that reference `index=sysmon` or `index=windows` won't return data (since the UF is no longer running on the victim). You have two options:

**Update your queries to use `index=velociraptor`.** Sample translations:

| Old query | New query |
|---|---|
| `index=sysmon EventCode=1 Image="*\\powershell.exe"` | `index=velociraptor sourcetype=_json artifact="Windows.System.Pslist" Name="powershell.exe"` |
| `index=windows EventCode=4688 New_Process_Name="*cmd.exe"` | `index=velociraptor artifact="Windows.EventLogs.EvtxHunter" EventID=4688 NewProcessName="*cmd.exe"` |
| `index=windows EventCode=4624 LogonType=10` | `index=velociraptor artifact="Windows.EventLogs.EvtxHunter" EventID=4624 LogonType=10` |

The trainer's hunt packs haven't been auto-rewritten — the original Sysmon/Security index queries are still useful as references for what to hunt, and analysts learn more by translating them themselves to the actual telemetry available.

**Recommended Velociraptor artifacts for each technique:**

| Technique | Run this artifact, then SplunkUpload |
|---|---|
| T1059.001 PowerShell | `Windows.EventLogs.PowerShell.ScriptBlock` |
| T1547.001 Run Keys | `Windows.Sys.StartupItems` |
| T1053.005 Scheduled Tasks | `Windows.System.ScheduledTasks` |
| T1543.003 Services | `Windows.System.Services` |
| T1003.001 LSASS | `Windows.Memory.ProcessHandles` (filter for lsass) |
| T1021.001 RDP / T1021.002 SMB | `Windows.EventLogs.EvtxHunter` (4624, 5140) |
| T1070.001 Log clearing | `Windows.EventLogs.EvtxHunter` (1102, 104) |

---

## Troubleshooting

### `Generic.Forensic.SplunkUpload` says "connection refused"

Either the HEC port isn't published from Docker (see Step 2) or the URL in your Velociraptor config is wrong. Test with curl from the Velociraptor container/host:

```bash
curl -k https://<splunk-ip>:8088/services/collector/event \
  -H "Authorization: Splunk <your-token>" \
  -d '{"event": "test"}'
```

You should get `{"text":"Success","code":0}`. If you get a connection error, the port isn't reachable.

### HEC returns "Token disabled"

Check **Settings → Data inputs → HTTP Event Collector** — the global "All Tokens" toggle has to be Enabled (top of the page).

### Events arrive but `index=velociraptor` returns nothing

The token may be writing to a different index. Check the token's "Allowed indexes" and "Default index" settings — both should include `velociraptor`. Or search across all indexes:

```
index=* sourcetype=_json | head 20
```

### Velociraptor agent isn't connecting to the server

Different problem entirely — see the main README's troubleshooting section. Without an agent, no artifacts can run, so no events reach Splunk.

---

## Why this design

This pipeline mirrors real-world DFIR more than the old "auto-ingest everything" model:

| Real-world DFIR | This training environment |
|---|---|
| Analyst gets an alert | Analyst sees a session log entry |
| Analyst targets a host with EDR collections | Analyst runs Velociraptor artifacts |
| Analyst pulls specific evidence (memory, prefetch, MFT) | Same artifacts available |
| Evidence lands in case management / SIEM for analysis | Velociraptor → HEC → Splunk |
| Analyst writes detection from what they observed | Same |

The deliberate "I have to choose what to collect" step is the most valuable training friction in this whole platform. Don't bypass it.
