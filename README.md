# ADObjectCanvas

# ADObjectCanvas

### The Complete Picture of Every Object in Your Active Directory

> Single-file PowerShell. Single-file HTML report. Every object class, every domain, every replicating partition.

**Author:** Santhosh Sivarajan, Microsoft MVP
**Email:** [santhosh@sivarajan.com](mailto:santhosh@sivarajan.com)
**Latest Version:** 1.5.0
**License:** MIT

---

## Overview

ADObjectCanvas is a self-contained PowerShell script (no modules to install beyond stock RSAT, no external dependencies) that produces a single HTML report answering one simple question:

> **What is actually in my Active Directory?**

It enumerates every domain naming context, the forest Configuration NC, and any DNS application partitions, then groups every object by its most-specific `objectClass` to give you a complete census. No sampling, no guesswork — every object that exists in the directory is accounted for.

The report is designed for architects, auditors, identity engineers, and anyone inheriting an unfamiliar AD forest who needs to understand its shape and contents quickly.

---

## Why ADObjectCanvas?

Other AD reporting tools (including [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas)) document **how AD is configured** — FSMO roles, replication topology, GPO settings, password policies, ADCS, LAPS. ADObjectCanvas answers a different question: **what objects actually exist in this AD, and how many of each?**

| | ADCanvas | ADObjectCanvas |
|---|---|---|
| **Primary question** | How is AD configured? | What is in AD? |
| **Headline view** | Forest, FSMO, replication topology | Per-domain object class census |
| **User detail** | Counts + service accounts + privileged groups | Counts + audit flags (AdminCount, smartcard, never-logged-on, inactive 90d, pwd-never-expires) |
| **Configuration NC** | Sites, subnets, FSMO holders | Every objectClass in Config NC, categorized |
| **DNS** | AD-integrated zone list | Zone list **plus** per-application-partition object census |
| **Cleanup view** | Not applicable | Heritage & Cleanup Candidates section |
| **Domain comparison** | Side-by-side replication health | Side-by-side stacked-bar charts for all major metrics |

The two are complementary. Run ADCanvas to document how AD is configured; run ADObjectCanvas to document what AD contains.

---

## What's in the Report

A single self-contained HTML file. No external CDN, no JavaScript libraries, no fonts to download. You can email it, archive it to SharePoint, or open it on an air-gapped network. Every visualization renders inline.

**Report structure:**

### 1. Executive Summary
Eight headline numbers — Total Objects, Users, Computers, Groups, OUs, GPOs, DCs, DNS Zones — with forest mode, schema OS (e.g. "Windows Server 2025"), Recycle Bin status, and tombstone lifetime as quick-reference tags.

### 2. Forest Summary
Forest name, mode, root domain, FSMO holders, schema version (with friendly OS mapping), schema class count, schema attribute count, AD Recycle Bin status, tombstone lifetime, plus a per-domain summary table and forest-wide totals card row.

### 3. All Domain Controllers
Flat table of every DC across the forest: name, IP, RWDC vs RODC, OS version, site, GC status, FSMO roles.

### 4. Forest-Wide Object Class Census
Every distinct `objectClass` found across all domain naming contexts, with counts and percentages, sorted descending. Each class is tagged with a **Category** (one of 16, see [Categories Reference](#object-categories) below) and a **friendly name** so the table reads as English, not raw LDAP.

### 5. Configuration Naming Context
Forest-wide configuration partition (`CN=Configuration,...`) — sites, services, ADCS templates, Exchange configuration, RBAC roles, DAC types, address book templates. Counted separately from domain NCs because Configuration NC replicates to every DC in every domain.

### 6. DNS Application Partitions
When DNS is AD-integrated, DNS records and zones live in `DomainDnsZones` (per-domain) and `ForestDnsZones` (forest-wide) application partitions rather than in the domain NC. This section enumerates each partition with object counts, dnsZone counts, and dnsRecord counts.

### 7. Heritage & Cleanup Candidates
Surfaces actionable items from the inventory above:

**Heritage** rows describe genuinely obsolete object types you may want to retire:
- **IPSec Legacy Policy Objects** — pre-Server 2008 IPSec policies (replaced by WFAS Connection Security Rules)
- **NTFRS Replication Objects** — pre-Server 2008 R2 file replication (replaced by DFSR)
- **NT4-Era Domain Policy** — `domainPolicy` objects retained for legacy NT4 SAM compatibility
- **Distributed Link Tracking** — link tracking volume and move tables (DLT service disabled by default since Server 2008 R2)

**Audit** rows flag items that are not necessarily wrong but should be reviewed:
- LSA Secrets count
- Tombstoned objects (no resolvable objectClass)
- Empty groups
- Stale computers (90+ days since password change)
- Never-logged-on enabled users
- Password-never-expires accounts

Each row includes a description of what the artifact is and a recommended action.

### 8. Per-Domain Sections
Each domain in the forest gets its own section with:
- **Object Class Census** — every objectClass in that domain's NC
- **Domain Controllers** — RWDC vs RODC, GC count, FSMO roles
- **User Accounts** — total, enabled, disabled, locked, password expired, password never expires, never logged on, inactive 90d+, AdminCount=1, smartcard-required
- **Computer Accounts** — total, enabled, disabled, servers, workstations, stale 90d+
- **Groups** — total, security, distribution, global, domain local, universal, empty, builtin, privileged
- **Organizational Units** — total, protected vs unprotected, container count
- **Group Policy Objects** — total, all enabled, all disabled, user/computer settings off
- **Service Accounts** — sMSA, gMSA, dMSA (Server 2025 schema 91+)
- **Other Objects** — contacts, printers, foreign security principals, BitLocker recovery keys
- **Default Domain Password Policy**
- **Fine-Grained Password Policies**

### 9. Configuration & Topology
- Trust Relationships (forest-wide, with direction, type, transitivity, selective auth)
- DNS Zones (forward, reverse, AD-integrated, file-backed, DNSSEC-signed)
- Sites, Subnets, Site Links
- Schema metadata (version, class count, attribute count, schema master)

### 10. Forest-Wide Object Charts
Nine donut and bar charts giving the executive view: Object Categories, Top Object Classes, User Account Status, Computer Account Status, Group Types, GPO Status, DNS Zones, Operating Systems, Objects per Domain.

### 11. Per-Domain Comparison Charts
Five horizontal stacked-bar charts comparing all domains side-by-side, normalized to 100% so distribution shape is comparable regardless of absolute domain size:
- User Status by Domain
- Computer Status by Domain
- Group Types by Domain
- GPO Status by Domain
- Object Categories by Domain

Hover any segment for exact counts.

---

## Object Categories

Every objectClass in the report is tagged with one of 16 categories, making the long tail navigable:

| Category | What's in it |
|---|---|
| **Identity** | user, computer, group, contact, inetOrgPerson, foreignSecurityPrincipal |
| **Service Account** | gMSA, sMSA, dMSA |
| **Structure** | OU, container, builtinDomain, domainDNS, lostAndFound, crossRef, partition references |
| **Policy** | groupPolicyContainer, msDS-PasswordSettings (FGPP), Password Settings Container, NT4 domainPolicy |
| **Security** | BitLocker recovery, LSA secrets, Extended Access Rights, Dynamic Access Control types |
| **PKI** | Certificate Templates, CA Service, PKI Enterprise OIDs |
| **Trust** | trustedDomain |
| **DNS** | dnsNode, dnsZone, DNS Server Settings |
| **Topology** | AD sites, subnets, site links, NTDS connections, NTDS DSA, NTDS Settings |
| **Display** | displaySpecifier, displayTemplate, addressTemplate, address book containers, DS UI Settings, Subschema |
| **Replication** | DFSR (all variants), DFS Configuration, NTFRS legacy |
| **IPSec** | IPSec Policy / Negotiation / ISAKMP / Filter / NFA (all legacy) |
| **Exchange** | Exchange schema artifacts (msExch* classes) |
| **Resource** | printQueue, volume, serviceConnectionPoint |
| **System** | RID Set/Manager, link tracking, SAM Server, RPC, classStore, MSMQ, IntelliMirror, TPM, WMI, ACS QoS legacy |
| **Other** | Anything not yet categorized (ideally near zero — drop me an issue if you see classes here) |

Class names not explicitly mapped fall through a heuristic chain (`msDFSR-*` → Replication, `nTDS*` → Topology, `msExch*` → Exchange, `msDS-*Claim*` → Security, etc.) so even classes I haven't enumerated by name should land in a sensible category.

---

## Requirements

- Windows machine joined to the forest you want to inventory
- RSAT Active Directory PowerShell module (`Import-Module ActiveDirectory`)
- Domain user credentials with read access (Domain Admin gives more accurate counts on `secret` and BitLocker recovery objects — see [Permissions Notes](#permissions-notes))
- Optional: DnsServer module on the box, for the legacy DNS zone list section
- PowerShell 5.1 or 7+

No external modules to install. No internet connection required at runtime.

---

## Usage

```powershell
.\ADObjectCanvas.ps1
```

The script writes `ADObjectCanvas_<timestamp>.html` to the same directory it was launched from.

To write to a different folder:

```powershell
.\ADObjectCanvas.ps1 -OutputPath C:\Reports
```

The script auto-creates the output directory if it doesn't exist. Paths with spaces are handled correctly.

---

## Output

A single HTML file, typically 100-200 KB. Dark navy theme with a print-friendly stylesheet. Sidebar navigation with section anchors and active-section highlighting on scroll. Sticky table headers, hover-highlighted rows, native browser tooltips on chart segments.

Open it locally, send it as an email attachment, or drop it on a SharePoint document library — no rendering server needed.

---

## Performance & Scale

The headline census uses **paged DirectorySearcher streaming** (PageSize=1000) rather than materializing the full result set into memory before counting. This means:

- **Lab environment (under 5,000 objects):** seconds
- **Mid-size AD (50,000 objects per domain):** under a minute per domain
- **Large enterprise (500,000+ objects per domain):** a few minutes per domain, memory stays bounded

If the streaming path fails for any reason (rare — usually a binding edge case), the script falls back to `Get-ADObject -Filter *` with a yellow warning so you know it took the slow path.

OU and GPO tables are capped at the first 200 entries to keep the HTML report a sensible size. The full counts are still shown.

---

## Permissions Notes

Some object counts depend on the running account's read permissions:

- **`secret` (LSA Secrets)** — typically only readable by Domain Admins or members of pre-authorized security groups. Standard domain users will often see 0 even when secrets exist.
- **`msFVE-RecoveryInformation` (BitLocker keys)** — by default only readable by Domain Admins or the BitLocker recovery group.

For accurate counts on these classes, run the script as a Domain Admin or equivalent. The Heritage & Cleanup section flags this caveat in the report itself.

For everything else (users, computers, groups, OUs, GPOs, schema, sites, etc.), standard domain user read access is sufficient.

---

## What Insights to Look For

A few patterns the report surfaces well:

**Heritage cleanup** — the Heritage & Cleanup section will tell you whether your environment carries pre-Server 2008 IPSec policies, pre-Server 2008 R2 NTFRS objects, or NT4-era `domainPolicy` artifacts. These are usually safe to clean up after audit.

**Domain population shape** — the per-domain "Object Categories by Domain" stacked bar reveals at a glance which domains are populated (heavy on Identity) vs scaffolding (heavy on Structure with few users). Useful when assessing whether to consolidate sparsely-populated domains.

**Stale computer concentration** — the per-domain "Computer Status by Domain" chart shows whether stale computers (90d+) are spread evenly or concentrated in one domain (often the case after a migration left orphaned objects in the source domain).

**Service account modernization** — sMSA / gMSA / dMSA counts per domain show progress toward modernization. dMSA appears only when schema is at version 91 (Server 2025) or higher.

**Configuration NC growth** — the Configuration NC section will reveal Exchange schema footprint (often the largest single contributor in any forest that has hosted Exchange), DAC types, ADCS template count, and similar forest-level metadata.

**DNS zone hosting model** — the DNS Application Partitions section tells you whether DNS records live in `DomainDnsZones`, `ForestDnsZones`, or the legacy domain NC, plus DNSSEC signing status.

---

---

## License

MIT — Free to use, modify, and distribute. See [LICENSE.txt](LICENSE.txt).

---

## Canvas Suite

Part of the open-source **Canvas Suite** of single-file AD and identity tools:

**Documentation:**
- [ADCanvas](https://github.com/SanthoshSivarajan/ADCanvas) — Active Directory configuration documentation
- [ADObjectCanvas](https://github.com/SanthoshSivarajan/ADObjectCanvas) — AD object inventory (this tool)
- [EntraIDCanvas](https://github.com/SanthoshSivarajan/EntraIDCanvas) — Entra ID documentation
- [IntuneCanvas](https://github.com/SanthoshSivarajan/IntuneCanvas) — Intune documentation

**Security:**
- [DelegationCanvas](https://github.com/SanthoshSivarajan/DelegationCanvas) — AD delegation analysis
- [NHICanvas](https://github.com/SanthoshSivarajan/NHICanvas) — Non-human identity governance
- [AttackPathCanvas](https://github.com/SanthoshSivarajan/AttackPathCanvas) — Identity attack path visualization
- [ZeroTrustCanvas](https://github.com/SanthoshSivarajan/ZeroTrustCanvas) — Zero Trust posture assessment

---

*Developed by Santhosh Sivarajan, Microsoft MVP.*
*Found a bug or have an idea? Open an issue on GitHub.*
