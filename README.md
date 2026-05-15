# MyFirstHack — Building and Validating a SIEM from Scratch

A hands-on home-lab project: build a Wazuh SIEM, ship logs from a Windows victim VM, write custom Sigma-style detection rules, and validate them with Atomic Red Team. Documents both the wins **and the real-world telemetry gaps** encountered while doing it.

**Author:** [@IshaanMotwani26](https://github.com/IshaanMotwani26)
**Date:** May 2026

---

## TL;DR

I deployed a Wazuh 4.7.0 SIEM in Docker, built a Windows 11 victim VM with Sysmon and the Wazuh agent, wrote three custom MITRE-aligned detection rules, and validated each one with a corresponding Atomic Red Team attack. Along the way I hit a real Sysmon ProcessAccess telemetry gap on Windows 11, diagnosed it across the full pipeline (Sysmon → Wazuh agent → manager → dashboard), and made the engineering decision to redesign one rule rather than ship a rule that couldn't be validated.

**Three rules. Three validated detections. One honest writeup of what didn't work.**

---

## Architecture

See [ARCHITECTURE.md](ARCHITECTURE.md) for a Mermaid diagram of the full pipeline.

**Components:**

| Component | Location | Purpose |
|---|---|---|
| Wazuh Manager + Indexer + Dashboard | Host (Docker, 192.168.0.140) | Rule engine, log storage, UI |
| Wazuh Agent | Win11 VM (192.168.0.216) | Ships Windows Event Log to manager |
| Sysmon (SwiftOnSecurity config) | Win11 VM | Endpoint telemetry — process create, network, etc. |
| Atomic Red Team | Win11 VM | MITRE ATT&CK adversary emulation library |
| `local_rules.xml` | Manager `/var/ossec/etc/rules/` | Custom detection rules |

---

## Detection rules

All three rules are children of Sysmon EventID 1 (ProcessCreate). Source: [`local_rules.xml`](local_rules.xml).

### Rule 100001 — PowerShell encoded command (T1059.001)

**Level:** 12 (high)
**Detects:** `powershell.exe` invoked with `-EncodedCommand` (or any abbreviation: `-e`, `-en`, `-enc`, ... `-encodedcommand`). Attackers use base64-encoded payloads to bypass naive content filters and command-line logging.

**Validation:** ran
```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAdABlAHMAdAAnAA==
```
(which decodes to `Write-Host 'Hello test'` — completely benign). Rule fired as expected. Wazuh's built-in rule 92057 also fired on the same event, which is the realistic outcome — multiple overlapping detections is normal in production SOCs.

### Rule 100002 — System & account reconnaissance (T1033, T1087)

**Level:** 8 (medium)
**Detects:** Process create where the image is one of `whoami.exe`, `net.exe`, `net1.exe`, `quser.exe`, or `hostname.exe`. Catches the very first commands almost every attacker runs post-exploitation to figure out who they are, what users exist, and what machine they landed on.

**Validation:** ran `whoami` and `net user`. Rule fired (see `screenshots/01-dashboard-overview.png`).

### Rule 100003 — Suspicious certutil usage (T1140, T1105)

**Level:** 12 (high)
**Detects:** `certutil.exe` invoked with any of `-decode`, `-encode`, `-urlcache`, `-decodehex`, or `-verifyctl`. `certutil` is a built-in Windows binary that's frequently abused as a LOLBin to download remote payloads or decode obfuscated files.

**Validation:** ran
```cmd
certutil -encode C:\Windows\System32\drivers\etc\hosts C:\Tools\hosts.b64
```
Rule fired (level 12, T1140/T1105 in MITRE field). Evidence in `screenshots/02-alert-table.png` and `screenshots/03-alert-mitre.png`.

---

## Validation summary

| Rule | MITRE | Level | Atomic / Test | Result |
|---|---|---|---|---|
| 100001 | T1059.001 | 12 | Manual `-EncodedCommand` PowerShell | ✅ Fired |
| 100002 | T1033, T1087 | 8 | `whoami`, `net user` | ✅ Fired |
| 100003 | T1140, T1105 | 12 | `certutil -encode` | ✅ Fired |

Final dashboard: 3 alerts, 2 at level 12+, 5 MITRE techniques covered.

---

## What didn't work: the LSASS investigation

The original plan included a fourth rule targeting **T1003.001 — OS Credential Dumping (LSASS Memory)** using Sysmon EventID 10 (ProcessAccess). I wrote the rule, then attempted to validate it with Atomic Red Team test `T1003.001-2` (LSASS dump via `comsvcs.dll`). It failed to fire, repeatedly. Diagnosing this turned into a multi-hour investigation that I think is actually the most valuable part of the project.

**Symptom:** Atomic test ran successfully (`Exit code: 0`), `lsass-comsvcs.dmp` was produced, but no Sysmon EventID 10 events appeared in the Windows Event Log and no Wazuh alerts fired.

**What I checked, in order:**

1. **Is Defender re-enabling itself silently?** Yes — periodically. Re-disabled `DisableRealtimeMonitoring`, `DisableBehaviorMonitoring`, `DisableIOAVProtection`, `DisableScriptScanning`. No change.
2. **Is Sysmon logging *anything*?** Yes — EventID 1 and EventID 11 flowed normally.
3. **Is Sysmon's config silently filtering ProcessAccess?** Inspected the SwiftOnSecurity config and found `<!-- <ProcessAccessConfig/> -->` — ProcessAccess is **commented out by default** in SwiftOnSecurity's config. Added a minimal patch config (`sysmon-lsass-patch.xml`) that explicitly enables ProcessAccess monitoring for LSASS targets.
4. **Did the patched config load?** Yes — verified via `Sysmon64.exe -c` that the config hash changed and the new `<ProcessAccess>` rule was visible in the runtime dump.
5. **Did EventID 10 fire after the config change?** No. Still zero events.
6. **Is LSA Protection (PPL) preventing Sysmon's driver from seeing handle opens to LSASS?** Registry `RunAsPPL` was not set, so theoretically no — but Windows 11 23H2+ has additional protections that aren't reflected in that one registry value.
7. **Was the config change actually picked up by the driver?** Uninstalled and reinstalled Sysmon entirely with `Sysmon64.exe -u` and `Sysmon64.exe -i ...`. Still no EventID 10.
8. **Did replacing the config accidentally disable other event types?** Yes — my minimal patch only declared `<ProcessAccess>`, which silently disabled EventID 1 logging in some scenarios. Reverted to SwiftOnSecurity config to restore baseline.

**Conclusion:** On this Windows 11 Enterprise Evaluation host, Sysmon's ProcessAccess hook does not generate EventID 10 for the `rundll32 → comsvcs.dll → MiniDump → LSASS` chain. This is consistent with LSA Protection silently affecting driver visibility in newer Windows 11 builds, or a Sysmon-on-Win11 interaction not yet publicly documented.

**Engineering decision:** Rather than ship a detection rule I couldn't validate, I dropped the EventID 10–based rule and re-scoped my detection portfolio to three rules that all use Sysmon EventID 1 — telemetry I'd already proven works end-to-end. This is the same call a working SOC analyst makes regularly: a detection you can't trigger in your environment is worse than no detection, because it gives false confidence in coverage.

The patch config I built lives in [`sysmon-lsass-patch.xml`](sysmon-lsass-patch.xml) for reference. **Anyone running this lab on a Windows 11 host where EventID 10 does work** can use that patch + a rule like:

```xml
<rule id="100099" level="13">
    <if_sid>92038</if_sid>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)\\lsass\.exe$</field>
    <field name="win.eventdata.grantedAccess" type="pcre2">0x(1010|1410|1438|143a|1fffff)</field>
    <description>Suspicious access to LSASS process memory (T1003.001)</description>
    <mitre><id>T1003.001</id></mitre>
</rule>
```

---

## Lessons learned

1. **Telemetry availability is a precondition for detection, not an assumption.** A rule that's syntactically perfect but tied to a missing log source is worse than useless.
2. **SwiftOnSecurity's Sysmon config is conservative by default.** Several event types (notably ProcessAccess and PipeCreated) are commented out as documentation. Read the config before assuming coverage.
3. **Windows 11 silently undoes Defender disable settings** after reboots, snapshots, and sometimes Windows Update activity. Snapshot before every attack and re-verify Defender state.
4. **Wazuh's `<if_sid>` chaining is powerful but unforgiving.** A rule child of `92052` will never fire if Sysmon doesn't generate the parent event in the first place. Always check the parent rule fires before debugging the child.
5. **VM snapshots are non-negotiable.** I bricked the VM with a botched Guest Additions install and rolled back to `Pre-Attack-2-LSASS` in 30 seconds with zero data loss on the project side.

---

## Setup (if you want to reproduce)

### Prerequisites
- Windows 11 host with 16+ GB RAM
- Docker Desktop
- VirtualBox
- Windows 11 Enterprise Evaluation ISO

### Deploy Wazuh
```powershell
git clone https://github.com/wazuh/wazuh-docker.git
cd wazuh-docker/single-node
docker-compose -f generate-indexer-certs.yml run --rm generator
docker-compose up -d
```
Dashboard at `https://localhost`, default admin/SecretPassword.

### Build the VM
1. Install Windows 11 Eval in VirtualBox with bridged networking
2. Disable Defender (Tamper Protection off → `Set-MpPreference -DisableRealtimeMonitoring $true ...`)
3. Install Sysmon with SwiftOnSecurity config:
```powershell
   Invoke-WebRequest -Uri "https://raw.githubusercontent.com/SwiftOnSecurity/sysmon-config/master/sysmonconfig-export.xml" -OutFile sysmonconfig.xml
   .\Sysmon64.exe -i sysmonconfig.xml -accepteula
```
4. Install Wazuh agent, enroll against manager IP
5. Install Atomic Red Team:
```powershell
   IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics
```

### Deploy the rules
```powershell
docker cp local_rules.xml single-node-wazuh.manager-1:/var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 chown wazuh:wazuh /var/ossec/etc/rules/local_rules.xml
docker exec single-node-wazuh.manager-1 /var/ossec/bin/wazuh-control restart
```

### Run the validation attacks
```powershell
# Rule 100001 — encoded PowerShell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ASABvAHMAdAAgACcASABlAGwAbABvACAAdABlAHMAdAAnAA==

# Rule 100002 — reconnaissance
whoami
net user

# Rule 100003 — certutil LOLBin
certutil -encode C:\Windows\System32\drivers\etc\hosts C:\Tools\hosts.b64
```

Check the dashboard with query `rule.id: 100001 or rule.id: 100002 or rule.id: 100003`.

---

## Project artifacts

| File | Purpose |
|---|---|
| `local_rules.xml` | The three custom detection rules |
| `local_rules.final.xml` | Snapshot of final ruleset |
| `sysmon-lsass-patch.xml` | The ProcessAccess config patch from the LSASS investigation (see "What didn't work" above) |
| `evidence-myfirsthack-alerts.json` | Filtered Wazuh alerts that fired during validation |
| `ARCHITECTURE.md` | Mermaid diagrams of the pipeline |
| `screenshots/` | Dashboard hits and rule details |

---

## Future work

- **Try the LSASS detection on Windows Server / non-Eval Windows 11** to see if the EventID 10 issue persists or is specific to the Eval edition
- **Add T1218.011 (rundll32 LOLBin) rule** with broader command-line patterns once the comsvcs.dll case can be reliably triggered
- **Tune the recon rule (100002)** to use frequency analysis — single `whoami` is medium-severity, but five recon commands in 30 seconds from one user is high-severity
- **Add Sigma rule equivalents** in YAML and use [sigma-cli](https://github.com/SigmaHQ/sigma-cli) to convert to Wazuh syntax for portability

---

## License

This project is released for educational use. Code is MIT-licensed. SwiftOnSecurity Sysmon config and Atomic Red Team have their own licenses — see their respective repositories.
