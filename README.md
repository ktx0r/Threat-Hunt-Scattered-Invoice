# Threat Hunt: Scattered Spider BEC
### Microsoft Sentinel / Log Analytics Workspace | BEC Investigation

---

| | |
|---|---|
| **Environment** | Microsoft Sentinel — Log Analytics Workspace (`law-cyber-range`) |
| **Analyst** | *Katie aka ktx0r* |
| **Hunt Type** | Hypothesis-Driven / Incident-Triggered |
| **Telemetry** | `SigninLogs` · `CloudAppEvents` · `EmailEvents` |
| **Hunt Window** | 2026-02-25 21:00 UTC → 2026-02-26 00:00 UTC |
| **Threat Actor** | Scattered Spider (UNC3944 / Octo Tempest) |
| **Verdict** | ⚠ Confirmed Threat — Full BEC Kill Chain |
| **Financial Exposure** | £24,500 fraudulent wire transfer (frozen by external bank fraud detection) |

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Hypothesis & Scope](#2-hypothesis--scope)
3. [Investigation](#3-investigation)
4. [Attack Timeline](#4-attack-timeline)
5. [Confirmed Findings](#5-confirmed-findings)
6. [MITRE ATT&CK Mapping](#6-mitre-attck-mapping)
7. [Detection Gaps](#7-detection-gaps)
8. [Recommendations](#8-recommendations)
9. [Detection Rules Created](#9-detection-rules-created)
10. [Final Assessment](#10-final-assessment)
11. [Analyst Notes](#11-analyst-notes)
12. [Lessons Learned & Next Hunt Hypotheses](#12-lessons-learned--next-hunt-hypotheses)
13. [Evidence Index](#13-evidence-index)

---

## 1. Executive Summary

This hunt investigated a confirmed Business Email Compromise targeting the finance department of LogN Pacific Financial Services, conducted in Microsoft Sentinel's Log Analytics Workspace across three telemetry sources covering a two-hour window on the evening of 25 February 2026.

The investigation confirmed a complete kill chain attributed to **Scattered Spider (UNC3944)** — a financially motivated threat group known for high-profile intrusions against MGM Resorts, Caesars Entertainment, and multiple UK financial institutions. The attacker obtained valid credentials via infostealer malware, bypassed MFA through push bombing, accessed the victim mailbox via Outlook Web, established two covert inbox rules to forward financial communications externally and permanently delete security alert notifications, then executed a thread-hijacked BEC resulting in a **£24,500 fraudulent wire transfer attempt**.

The full attack — from initial MFA approval to fraud email sent — occurred in **under 35 minutes** without triggering a single internal alert. Funds were frozen only due to external bank-side fraud detection. The investigation confirms critical gaps in conditional access enforcement, MFA policy, mailbox monitoring, and detection coverage across the environment.

---

## 2. Hypothesis & Scope

### Hypothesis

> *"A threat actor has obtained valid credentials for an internal finance account and is actively using that access to intercept financial communications and execute wire transfer fraud."*

### Hunt Trigger

Hunt initiated following a bank fraud alert flagging a £24,500 wire transfer to an unknown account. Finance department reported receiving an email from internal employee Mark Smith containing updated vendor banking details. Smith later confirmed he had received repeated MFA push notifications the previous evening and approved one to make them stop. Investigation scope set to the 21:00–23:00 UTC window on 25 February 2026.

### Data Sources

| Source | Platform | Coverage |
|---|---|---|
| `SigninLogs` | Microsoft Entra ID | Authentication events, MFA status, device and location data |
| `CloudAppEvents` | Microsoft Defender for Cloud Apps | Mailbox activity, inbox rule creation, cloud app access |
| `EmailEvents` | Microsoft Defender for Office 365 | Email send/receive events, sender IP, direction, subject |

---

## 3. Investigation

### Phase 1 — Identity Confirmation

The investigation began by confirming the identity of the user named in the bank fraud alert. Queried `SigninLogs` for the display name provided by the IR lead.

```kql
SigninLogs
| where UserDisplayName has "mark"
| distinct UserPrincipalName, UserDisplayName
```

![Identity pivot — m.smith@lognpacific.org confirmed](screenshots/01-identity-pivot.png)

**Result:** `m.smith@lognpacific.org` confirmed as the compromised account. All subsequent queries pivot on this identity and the attacker IP identified in Phase 2.

---

### Phase 2 — Authentication Analysis

Pulled the full sign-in history for the identified account across the attack window, sorted chronologically to establish the sequence of events. Filtered to result types relevant to MFA fatigue investigation: successful authentications (`0`), MFA not satisfied (`50074`), and MFA interrupt (`50140`).

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where ResultType in (0, 50074, 50140)
| project TimeGenerated, IPAddress, Location, ResultType,
          AuthenticationRequirement, ConditionalAccessStatus
| order by TimeGenerated asc
```

![SigninLogs sequence — MFA fatigue pattern and attacker IP](screenshots/02-signin-sequence.png)

**Result:** Two distinct IPs present in the logs:
- `172.175.65.103` (US) — Mark's legitimate daytime session, `ResultType 0`
- `205.147.16.190` (NL) — attacker IP, appearing with the following sequence:
  - `ResultType 50074` × 2 — MFA required, not satisfied
  - `ResultType 50140` × 1 — MFA interrupt
  - `ResultType 0` — successful authentication

This three-attempt sequence before success is consistent with an **MFA fatigue / push bombing attack** — repeated push notifications sent until the user approves one to stop the interruption. Mark later confirmed this is exactly what happened.

`ConditionalAccessStatus: notApplied` was confirmed on the successful attacker session — no Conditional Access policy evaluated or enforced. This is the root cause that made the entire attack possible.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 50074
| count
```

![MFA denial count — 2 confirmed 50074 entries](screenshots/03-mfa-count.png)

**Result:** 2 × `ResultType 50074` confirmed from the attacker IP within the attack window.

---

### Phase 3 — Device Profile Analysis

Queried device and browser details for the attacker session to confirm it did not originate from a managed corporate endpoint.

```kql
SigninLogs
| where UserPrincipalName == "m.smith@lognpacific.org"
| where IPAddress == "205.147.16.190"
| where ResultType == 0
| project TimeGenerated, UserAgent, DeviceDetail
| take 1
```

![Device profile — Ubuntu Linux, Firefox 147.0, isCompliant: false, isManaged: false](screenshots/04-device-profile.png)

**Result:** The attacker session originated from an **unmanaged Ubuntu Linux endpoint running Firefox 147.0** — entirely inconsistent with the organization's managed Windows / Microsoft Edge baseline.

| Field | Value |
|---|---|
| Operating System | Linux (Ubuntu) |
| Browser | Firefox 147.0 |
| isManaged | false |
| isCompliant | false |
| UserAgent | `Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:147.0) Gecko/20100101 Firefox/147.0` |

Three simultaneous anomaly signals on this session: foreign country, unmanaged OS, non-corporate browser. No alert fired on any of them.

---

### Phase 4 — Post-Authentication Activity

Pivoted to `CloudAppEvents` to map everything the attacker did after gaining access, sorted chronologically to reveal intent through sequencing.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| project TimeGenerated, ActionType, AccountDisplayName, ObjectName, RawEventData
| order by TimeGenerated asc
```

![CloudAppEvents full sequence — complete post-auth attack sequence](screenshots/05-cloudappevents-sequence.png)

**Result:** The full post-authentication sequence:

| Time (UTC) | ActionType | Significance |
|---|---|---|
| 21:56 | `MailItemsAccessed` | Mailbox reconnaissance — reading financial threads |
| 21:57 | `MailItemsAccessed` | Continued reconnaissance |
| 22:02 | `New-InboxRule` | Rule 1 created (name: `.`) |
| 22:03 | `New-InboxRule` | Rule 2 created (name: `..`) |
| 22:04 | `Create` | Fraud email drafted |
| 22:04 | `MailItemsAccessed` | Final inbox check before sending |
| 22:06 | `Send` | Fraudulent BEC email sent |
| 22:07 | `FileAccessed` | OneDrive file accessed |
| 22:07 | `SignInEvent` | SharePoint session established |
| 22:07+ | `ListCreated`, `ListColumnCreated` | SharePoint/OneDrive structure modified |
| 22:07+ | `Broke sharing inheritance` | File sharing permissions altered |

The reconnaissance-before-persistence order is a hallmark of targeted BEC. An opportunistic actor establishes persistence immediately. A targeted actor reads the environment first to make the fraud convincing — the attacker needed to understand Mark's vendor relationships and active invoice threads before crafting a believable email.

---

### Phase 5 — Inbox Rule Analysis

Expanded the `RawEventData` on both `New-InboxRule` events to document the full rule configuration.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType == "New-InboxRule"
| project TimeGenerated, ActionType, ObjectName, RawEventData
| order by TimeGenerated asc
```

![Rule 1 RawEventData — full parameters including ForwardTo and keywords](screenshots/06-rule1-parameters.png)

![Rule 1 continued — StopProcessingRules, SessionId, UserId confirmed](screenshots/07-rule1-continued.png)

**Rule 1 — Financial Collection (name: `.`)**

| Parameter | Value |
|---|---|
| Name | `.` (single period) |
| ForwardTo | `insights@duck.com` |
| SubjectOrBodyContainsWords | `invoice, payment, wire, transfer` |
| StopProcessingRules | `True` |
| CreationTime | `2026-02-25T22:02:33Z` |
| SessionId | `00225cfa-a0ff-fb46-a079-5d152fcdf72a` |

![Rule 2 parameters — deletion keywords and DeleteMessage: True](screenshots/08-rule2-parameters.png)

**Rule 2 — Security Alert Suppression (name: `..`)**

| Parameter | Value |
|---|---|
| Name | `..` (double period) |
| SubjectOrBodyContainsWords | `suspicious, security, phishing, unusual, compromised, verify` |
| DeleteMessage | `True` |
| StopProcessingRules | `True` |

Rule 2 is the counter-detection layer. The keyword list maps closely to the language Microsoft Entra ID uses in its anomalous sign-in notification emails. The attacker specifically engineered around Microsoft's own security notification system — these emails would have been permanently deleted before Mark ever saw them.

---

### Phase 6 — Fraud Execution

Pivoted to `EmailEvents` to locate the fraudulent email and confirm attribution to the attacker session.

```kql
EmailEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where SenderIPv4 == "205.147.16.190"
| project TimeGenerated, SenderFromAddress, RecipientEmailAddress,
          Subject, EmailDirection, SenderIPv4
```

![EmailEvents fraud email — full expanded row showing all fields](screenshots/09-fraud-email.png)

**Result:**

| Field | Value |
|---|---|
| Timestamp | `2026-02-25T22:06:39Z` |
| Sender | `m.smith@lognpacific.org` |
| Recipient | `j.reynolds@lognpacific.org` |
| Subject | `RE: Invoice #INV-2026-0892 - Updated Banking Details` |
| Direction | `Intra-org` |
| Sender IP | `205.147.16.190` |

The `RE:` prefix confirms **thread hijacking** — the attacker located an active invoice conversation during the Phase 4 reconnaissance and inserted fraudulent banking details as a trusted reply. `Intra-org` delivery bypassed all external sender reputation checks, SPF/DKIM/DMARC validation, and phishing filters. The sender IP match across `SigninLogs` and `EmailEvents` provides definitive cross-table attribution.

---

### Phase 7 — Scope Expansion

Queried for cloud storage and application access beyond the mailbox to assess the full data exposure footprint.

```kql
CloudAppEvents
| where TimeGenerated between (datetime(2026-02-25T21:00:00Z) .. datetime(2026-02-26T00:00:00Z))
| where IPAddress == "205.147.16.190"
| where ActionType != "MailItemsAccessed"
    and ActionType != "New-InboxRule"
    and ActionType != "Send"
| project TimeGenerated, ActionType, Application, AccountDisplayName, ObjectName
| order by TimeGenerated asc
```

![Scope expansion — OneDrive and SharePoint access with Broke sharing inheritance events](screenshots/10-scope-expansion.png)

**Result:** Following fraud execution the attacker accessed:
- `Microsoft OneDrive for Business` — file access, list creation, sharing permission changes
- `Microsoft SharePoint Online` — session established, additional list activity

Notably, `Broke sharing inheritance` events appeared on OneDrive items — indicating the attacker altered file sharing permissions, potentially staging files for external access. The full scope of data exposed requires a targeted file access audit against the session ID.

---

### Phase 8 — Session Correlation

Confirmed all attacker activity across all three tables originated from a single authenticated session.

**Session ID:** `00225cfa-a0ff-fb46-a079-5d152fcdf72a`

Confirmed present in:
- `SigninLogs` — successful authentication event
- `CloudAppEvents` — `AppAccessContext.AADSessionId` in Rule 1 RawEventData
- `EmailEvents` — correlates to the same authenticated session

Single session confirmation scopes the minimum containment action to revocation of this specific token.

---

## 4. Attack Timeline

```
── PRE-COMPROMISE ────────────────────────────────────────────────────────────

  [Prior to hunt window]
       Infostealer malware harvests credentials for m.smith@lognpacific.org
       Credential logs acquired by Scattered Spider operator

── INITIAL ACCESS ────────────────────────────────────────────────────────────

  2026-02-25
  21:54 UTC     MFA push bombing begins — 205.147.16.190 (Netherlands)
  21:54–21:58   Two ResultType 50074 + one ResultType 50140 from attacker IP
  ~21:59 UTC    Mark approves MFA prompt — attacker gains authenticated session
                OS: Ubuntu Linux / Browser: Firefox 147.0
                isManaged: false / isCompliant: false
                ConditionalAccessStatus: notApplied

── RECONNAISSANCE ────────────────────────────────────────────────────────────

  21:56 UTC     First post-auth action: MailItemsAccessed
  21:57 UTC     Continued mailbox reading — vendor threads, invoice context

── PERSISTENCE ───────────────────────────────────────────────────────────────

  22:02 UTC     Rule 1 created (name: ".")
                → Forwards finance-keyword mail to insights@duck.com
                → StopProcessingRules: True

  22:03 UTC     Rule 2 created (name: "..")
                → Permanently deletes security alert emails
                → DeleteMessage: True / StopProcessingRules: True

── FRAUD EXECUTION ───────────────────────────────────────────────────────────

  22:04 UTC     Fraud email drafted using intercepted invoice context
  22:06 UTC     Email sent to j.reynolds@lognpacific.org
                Subject: RE: Invoice #INV-2026-0892 - Updated Banking Details
                Direction: Intra-org — bypasses all external filters
                Sender IP: 205.147.16.190 — matches attacker sign-in

── SCOPE EXPANSION ───────────────────────────────────────────────────────────

  22:07 UTC     Microsoft OneDrive for Business accessed
                FileAccessed, ListCreated, Broke sharing inheritance
  22:07 UTC     Microsoft SharePoint Online session established
                Session ID: 00225cfa-a0ff-fb46-a079-5d152fcdf72a

── DETECTION & CONTAINMENT ───────────────────────────────────────────────────

  2026-02-26    External bank fraud detection flags £24,500 wire transfer
                Funds frozen — no internal control contributed to detection
  [Post-event]  Hunt initiated; full kill chain confirmed across 3 data sources
                Sessions revoked; inbox rules deleted; credentials rotated
```

---

## 5. Confirmed Findings

### Finding 1 — Account Compromise via MFA Fatigue

| | |
|---|---|
| **Severity** | 🔴 Critical |
| **Account** | `m.smith@lognpacific.org` |
| **Attacker IP** | `205.147.16.190` (Netherlands) |
| **MFA Attempts** | 3 total — 2× `ResultType 50074`, 1× `ResultType 50140` |
| **Root Enabler** | `ConditionalAccessStatus: notApplied` |
| **Evidence** | SigninLogs: MFA failure sequence → ResultType 0 |

Attacker obtained a valid M365 session by generating repeated MFA push notifications until the user approved one. No Conditional Access policy evaluated or enforced the session despite a foreign IP, unmanaged device, and new geolocation all being present simultaneously.

---

### Finding 2 — Persistent Collection via Covert Inbox Rules

| | |
|---|---|
| **Severity** | 🔴 Critical |
| **Account** | `m.smith@lognpacific.org` |
| **Rule 1** | Name: `.` — forwards finance keywords to `insights@duck.com` |
| **Rule 2** | Name: `..` — permanently deletes security alert emails |
| **Created** | 22:02 and 22:03 UTC — 3 minutes after gaining access |
| **Evidence** | CloudAppEvents: New-InboxRule × 2, RawEventData parameters |

Two rules created in under 90 seconds — one to collect financial intelligence, one to suppress detection. Both configured with `StopProcessingRules: True` for rule priority dominance. Rule 2's `DeleteMessage: True` ensured permanent deletion of Microsoft security notifications, not just redirection.

---

### Finding 3 — Thread-Hijacked BEC / Fraudulent Wire Transfer

| | |
|---|---|
| **Severity** | 🔴 Critical |
| **Target** | `j.reynolds@lognpacific.org` |
| **Amount** | £24,500 |
| **Method** | Reply to active invoice thread with substituted banking details |
| **Outcome** | Wire transfer initiated; frozen by external bank fraud detection |
| **Evidence** | EmailEvents: sender IP match, Intra-org direction, RE: subject prefix |

Attacker used invoice context gathered during mailbox reconnaissance to craft a convincing thread-hijacked email. Delivered as Intra-org, bypassing all external controls. Near-miss prevented by bank-side detection — not any organizational control.

---

### Finding 4 — Cloud Storage Access and Permission Modification

| | |
|---|---|
| **Severity** | 🟠 High |
| **Scope** | Microsoft OneDrive for Business, Microsoft SharePoint Online |
| **Notable** | `Broke sharing inheritance` events — permissions altered on files/folders |
| **Status** | Full data exposure scope requires targeted file access audit |
| **Evidence** | CloudAppEvents: FileAccessed, ListCreated, Broke sharing inheritance |

Post-fraud activity extended beyond the mailbox into cloud storage. Sharing permission changes suggest potential data staging. Finance-role OneDrive and SharePoint access typically includes financial forecasts, vendor contracts, and payment authorization records.

---

### Finding 5 — Conditional Access Policy Gap (Root Cause)

| | |
|---|---|
| **Severity** | 🟠 High |
| **Evidence** | `ConditionalAccessStatus: notApplied` on successful attacker session |
| **Impact** | MFA enforcement not applied — single-factor auth succeeded from foreign IP |

The compromised account was not subject to MFA enforcement via Conditional Access. This single policy gap is the root cause that made every subsequent stage of the attack possible. The tooling to prevent this exists natively in the M365 stack — it was not configured.

---

## 6. MITRE ATT&CK Mapping

| Technique ID | Name | Tactic | Observed |
|---|---|---|---|
| T1078 | Valid Accounts | Initial Access / Persistence | Pre-obtained credentials used throughout |
| T1621 | MFA Request Generation | Credential Access | Push bombing — 3 attempts before success |
| T1114.002 | Remote Email Collection | Collection | MailItemsAccessed via Outlook Web |
| T1114.003 | Email Forwarding Rule | Collection | Rule 1 forwarding finance keywords externally |
| T1564.008 | Email Hiding Rules | Defense Evasion | Rules named `.` and `..` |
| T1070 | Indicator Removal | Defense Evasion | Rule 2 permanently deleting security alerts |
| T1566.002 | Spearphishing Link | Execution | Thread-hijacked BEC email |
| T1213.002 | Data from SharePoint | Collection | OneDrive and SharePoint accessed post-compromise |
| T1657 | Financial Theft | Impact | £24,500 fraudulent wire transfer |

**Threat Actor:** Scattered Spider — UNC3944 / Octo Tempest / G1015
TTP alignment confirmed across: infostealer credential sourcing, MFA fatigue, cloud-only execution, covert inbox rules with evasive naming, thread-hijacked BEC targeting financial personnel.

---

## 7. Detection Gaps

| Gap | Impact | Evidence |
|---|---|---|
| Conditional Access not enforced | MFA bypass via push bombing succeeded | `ConditionalAccessStatus: notApplied` |
| No MFA fatigue detection | 3 failures + success from same IP went unalerted | No alert fired |
| No inbox rule creation alerting | Two covert rules active with no detection | No alert on `New-InboxRule` |
| No impossible travel alerting | Netherlands login not flagged | No alert on first-time country |
| No device compliance enforcement | Unmanaged Linux device granted full M365 access | `isManaged: false` |
| External auto-forwarding not blocked | Financial emails forwarded to duck.com unimpeded | No transport rule |
| No intra-org BEC detection | Fraudulent email delivered without inspection | `Intra-org` bypasses filters |

---

## 8. Recommendations

### Immediate — 0 to 72 Hours
1. **Revoke all active sessions** for `m.smith@lognpacific.org` and force credential rotation
2. **Delete both inbox rules** (`.` and `..`) from the compromised mailbox
3. **Audit all finance department mailboxes** for dot-pattern or minimal-name rules
4. **Block `insights@duck.com`** at the email gateway
5. **Confirm with j.reynolds** no payment was processed; preserve the email thread as evidence

### Short-Term — 1 to 2 Weeks
6. **Enforce Conditional Access universally** — migrate finance and executive roles to phishing-resistant MFA (FIDO2 / number matching)
7. **Block external auto-forwarding** via Exchange transport rule
8. **Deploy Sentinel detection rules** for inbox rule anomalies and MFA fatigue (see §9)
9. **Enable impossible travel and new-ASN alerts** in Entra ID
10. **Enforce device compliance** in Conditional Access — block unmanaged devices

### Strategic — 30 to 90 Days
11. **Enable Continuous Access Evaluation (CAE)** to reduce session token reuse window
12. **Implement Defender for Office 365 Safe Links** with real-time detonation
13. **Establish out-of-band vendor payment verification** — banking detail changes require phone confirmation to a known contact
14. **Conduct BEC awareness training** for finance staff — thread hijacking, payment redirect red flags
15. **Implement MFA push rate limiting** — account lockout after N consecutive failures

---

## 9. Detection Rules Created

Two Sentinel analytics rules authored as a direct output of this hunt.

---

**Rule 1 — Suspicious Inbox Rule: Minimal or Obfuscated Name**

Fires when an inbox rule is created with a blank, single-character, or dot-pattern name.
Severity: **High** | MITRE: T1564.008

```kql
CloudAppEvents
| where ActionType == "New-InboxRule"
| extend RuleName = tostring(parse_json(RawEventData).ObjectName)
| where RuleName in ("", ".", "..")
    or string_size(RuleName) <= 2
| project TimeGenerated, AccountDisplayName, RuleName,
          IPAddress, ActionType, RawEventData
| order by TimeGenerated desc
```

---

**Rule 2 — MFA Fatigue: Repeated Failures Followed by Successful Authentication**

Fires when 2+ `ResultType 50074` events from the same IP are followed by `ResultType 0`
within a 15-minute window for the same user.
Severity: **Critical** | MITRE: T1621, T1078

```kql
let failures = SigninLogs
| where ResultType == 50074
| project FailTime = TimeGenerated, UserPrincipalName, IPAddress;
let successes = SigninLogs
| where ResultType == 0
| project SuccessTime = TimeGenerated, UserPrincipalName, IPAddress;
failures
| join kind=inner successes on UserPrincipalName, IPAddress
| where SuccessTime between (FailTime .. (FailTime + 15m))
| summarize FailCount = count(), FirstFail = min(FailTime),
            Success = min(SuccessTime) by UserPrincipalName, IPAddress
| where FailCount >= 2
| project UserPrincipalName, IPAddress, FailCount, FirstFail, Success
```

---

## 10. Final Assessment

This investigation confirms a complete six-stage BEC kill chain executed in under 35 minutes with **zero internal alerts** during the active attack window. The £24,500 wire transfer was stopped by an external bank fraud system — the only control in the entire chain that worked as intended is one the organization does not own or operate.

**Open Risk Items:**

| Risk | Status | Severity |
|---|---|---|
| Conditional Access not enforced | Open — remediation in progress | 🔴 Critical |
| External auto-forwarding not blocked | Open | 🔴 Critical |
| No inbox rule creation alerting | Resolved — rules deployed | ✅ Mitigated |
| No MFA fatigue detection | Resolved — rules deployed | ✅ Mitigated |
| Device compliance not enforced | Open | 🟠 High |
| No vendor payment change protocol | Open | 🟠 High |
| CAE not enabled | Open | 🟡 Medium |
| OneDrive/SharePoint data exposure scope | Under assessment | 🟠 High |

The attack succeeded entirely due to policy gaps, not technology gaps. Every control required to prevent this exists natively in the Microsoft 365 stack. Until Conditional Access is enforced universally and external forwarding is blocked, the organization remains straightforwardly vulnerable to a repeat attempt.

---

## 11. Analyst Notes

The two-rule combination is the most operationally significant detail in this investigation. Rule 1 is the expected BEC play — financial collection via forwarding. Rule 2 is the counter-detection layer, and it demonstrates the attacker specifically anticipated Microsoft's own notification system.

The keyword list in Rule 2 (`suspicious`, `security`, `phishing`, `unusual`, `compromised`, `verify`) maps closely to the exact language Microsoft Entra ID uses in anomalous sign-in notification emails. That precision is not accidental. This is a tested playbook built specifically to survive in M365 environments where Microsoft's native alerting is the primary detection mechanism. The attacker engineered around the defender's tooling, not just the victim's behavior.

The `DeleteMessage: True` setting on Rule 2 is worth calling out specifically. This isn't just hiding emails in a folder — it's permanent deletion. Even if the user went looking for security notifications they wouldn't find them. Combined with `StopProcessingRules: True` on both rules, the attacker ensured their configuration took absolute priority and left no trace in the inbox.

The 35-minute total window from MFA approval to fraud email is also notable. Reconnaissance took approximately 6 minutes. Rule creation took under 2 minutes. Fraud execution took approximately 3 minutes. The rest of the window is scope expansion. This is a rehearsed sequence, not improvised — the speed and precision suggests an experienced operator running a known playbook.

The `Intra-org` email direction remains the detail most likely to be missed. Organizations invest heavily in external phishing defenses — SPF, DKIM, DMARC, Safe Links. None of it applies to an email sent between two accounts in the same M365 tenant. Account-takeover BEC exploits this blind spot by design. Detection for this attack class has to be identity-first, not perimeter-first.

The `Broke sharing inheritance` events in OneDrive are an underexamined finding. In most BEC post-incident analyses the focus stays on the email chain and the wire transfer. The SharePoint and OneDrive activity here — especially permission changes — suggests the attacker may have been preparing for secondary data access or exfiltration beyond the immediate fraud objective. That thread deserves a dedicated follow-on investigation.

---

## 12. Lessons Learned & Next Hunt Hypotheses

### What This Hunt Demonstrated

- A complete BEC kill chain is fully reconstructable from three M365 telemetry sources — no single table tells the full story, but the three together leave almost nothing hidden
- The absence of alerts during the active attack window is itself a critical finding — 35 minutes of attacker activity in a monitored environment with zero detections is a maturity gap that must be communicated explicitly
- Behavioral IOCs (dot-pattern rule names, `StopProcessingRules`, security keyword deletion) are more durable detection signals than IP-based IOCs
- Reconnaissance-before-persistence ordering reliably distinguishes targeted BEC from opportunistic account abuse

### What Could Be Done Faster

- Pivoting directly from the bank alert to `ConditionalAccessStatus` in `SigninLogs` would have accelerated root cause identification significantly
- Querying `RawEventData` for inbox rule parameters should be a standard first step in any BEC hunt — the rule configuration tells the whole persistence story in one expanded view
- Session ID correlation across all three tables should be established early to confirm single-actor attribution before drawing conclusions

### Next Hunt Hypotheses

> **H-001:** *"The attacker IP 205.147.16.190 appears in sign-in attempts against other accounts in the environment outside the confirmed hunt window — the finance department may not have been the only target."*

> **H-002:** *"Specific files accessed or permission-modified in OneDrive during this session were staged for external access — a targeted file audit against session ID `00225cfa-a0ff-fb46-a079-5d152fcdf72a` may identify data that left the environment."*

> **H-003:** *"The infostealer that harvested Mark Smith's credentials may still be active on a device within scope — EDR telemetry predating this hunt window may show credential harvesting activity not visible in cloud identity logs."*

---

## 13. Evidence Index

| ID | Screenshot File | Source | Description |
|---|---|---|---|
| E-01 | `01-identity-pivot.png` | `SigninLogs` | m.smith@lognpacific.org confirmed as compromised account |
| E-02 | `02-signin-sequence.png` | `SigninLogs` | Full auth sequence — 50074 × 2, 50140 × 1, ResultType 0; two IPs visible |
| E-03 | `03-mfa-count.png` | `SigninLogs` | Count query confirming 2× ResultType 50074 from attacker IP |
| E-04 | `04-device-profile.png` | `SigninLogs` | Ubuntu Linux, Firefox 147.0, isCompliant: false, isManaged: false |
| E-05 | `05-cloudappevents-sequence.png` | `CloudAppEvents` | Full post-auth activity — MailItemsAccessed → rules → Send → SharePoint |
| E-06 | `06-rule1-parameters.png` | `CloudAppEvents` | Rule 1 RawEventData — name, ForwardTo, keywords, session ID |
| E-07 | `07-rule1-continued.png` | `CloudAppEvents` | Rule 1 continued — StopProcessingRules, SessionId, UserId, ResultStatus |
| E-08 | `08-rule2-parameters.png` | `CloudAppEvents` | Rule 2 parameters — name `..`, deletion keywords, DeleteMessage: True |
| E-09 | `09-fraud-email.png` | `EmailEvents` | Fraudulent BEC email — recipient, subject, Intra-org, sender IP match |
| E-10 | `10-scope-expansion.png` | `CloudAppEvents` | OneDrive/SharePoint access — FileAccessed, Broke sharing inheritance |
| E-11 | — | `SigninLogs` | Session ID `00225cfa-a0ff-fb46-a079-5d152fcdf72a` — visible in E-06/E-07 |
| E-12 | — | Sentinel | Detection Rule 1: Suspicious Inbox Rule — Minimal Name |
| E-13 | — | Sentinel | Detection Rule 2: MFA Fatigue Pattern |

---

*Katie Plaster · 04.18.2026*

*Scattered Spider BEC Investigation — Log(N) Pacific Financial Services [Simulated]*
