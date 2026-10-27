# RateMyAzureSubscriptions

Audit an Azure environment against Microsoft's best practices, grade six areas **A to F**, and turn every finding into a prioritised improvement plan.

RateMyAzureSubscriptions is a read-only Blazor Server app (the sibling of RateMyWAF, same layout and way of working). It conducts a comprehensive review of the selected subscriptions to assess the current configuration, identify potential risks, and highlight areas requiring attention, improvement or optimisation, focusing on security, governance, performance, reliability and cost. The findings are documented in Word reports and used to build a prioritised improvement plan with recommendations based on operational impact and Microsoft guidance.

| Area | What it reviews |
|---|---|
| **Compute** | Virtual machines, App Services and plans: sizing, configuration, availability, backup, performance and cost optimisation. |
| **Networking** | Virtual networks, subnets, NSGs, public IPs, private endpoints, DDoS, Bastion, Network Watcher and flow logs. |
| **Security** | Microsoft Defender for Cloud plans, secure score and recommendations, Azure Policy, Key Vault and SQL hardening, Activity Log export. |
| **Storage** | Storage accounts: access controls, network restrictions, redundancy, soft delete and versioning, lifecycle management, encryption. |
| **Microsoft Entra ID** | Conditional Access and MFA, legacy authentication, privileged roles, guest settings, user permissions, authentication methods. |
| **Identity and Access Management** | Azure RBAC assignments, Owners and privileged roles, groups vs users, custom roles, service principals, managed identities, orphaned and guest assignments. |

The flow is three steps: **Scope** (tenant, subscriptions and which areas to audit) → **Grades** (A–F per area with score breakdown, improvements, findings with fixes and scripts, inventory, Word reports) → **Improvement plan** (every finding grouped P1/P2/P3 with effort, filterable by area, downloadable as a Word document). Every report can also be copied as GitHub-flavoured Markdown, ready to paste into an issue.

## Scoring model

Every area is scored on its own 100-point scale from weighted categories, mapped to a letter, with hard caps so a good score cannot hide a critical gap. The full model is on the **Scoring model** page in the app. In short:

| Area | Categories (points) | Caps |
|---|---|---|
| Compute | Availability 25 · Backup 20 · Configuration & security 25 · Performance & sizing 15 · Cost 15 | unmanaged disks → B · no VM backed up → C |
| Networking | Segmentation 25 · Internet exposure 25 · Threat protection 15 · Monitoring 15 · Hygiene & cost 20 | management port open to the Internet → D · subnet without NSG → B |
| Security | Defender for Cloud 30 · Posture 20 · Policy & governance 15 · Encryption & secrets 20 · Logging 15 | no Defender plans → C · Activity Log not exported → B |
| Storage | Access control 30 · Network security 20 · Data protection 25 · Lifecycle & cost 15 · Encryption & configuration 10 | anonymous blob access → C · HTTP / TLS < 1.2 → C |
| Microsoft Entra ID | Conditional Access & MFA 35 · Privileged access 20 · External collaboration 15 · User settings 15 · Auth methods & risk 15 | no MFA enforcement → D · legacy auth not blocked → C |
| IAM | Least privilege 30 · Group-based access 15 · Workload identities 25 · Hygiene 15 · Scope discipline 15 | > 5 subscription Owners → C · wildcard custom role → B |

Grade bands: **A** ≥ 90 · **B** ≥ 75 · **C** ≥ 60 · **D** ≥ 45 · **E** ≥ 30 · **F** below. The overall grade is the letter for the average of the assessed areas, never more than one band above the weakest area. Areas with nothing to assess are marked "not assessed" and excluded.

Every improvement is listed with the points it gains and the grade it would produce, so the biggest win is always visible. Every finding carries a severity (which sets its priority), an effort estimate and, where a safe one-liner exists, an Azure CLI fix script you review and run yourself.

## Running it

Prerequisites: .NET 10 SDK, Azure CLI, and a signed-in account with Reader access to the subscriptions you want to audit.

```powershell
az login                       # optionally: az login --tenant <tenant-id>
cd src/RateMyAzureSubscriptions
dotnet run
```

Open <http://localhost:5220>, choose the subscriptions, audit, and read the grades.

### What is left out

Restore tests are never reviewed: any resource, subnet or resource group whose name contains **restore** (case-insensitive) is filtered out in the Resource Graph queries and again after collection, and role assignments scoped to such resource groups are dropped too. The Grades step shows the rule in force and how many collected resources were skipped. Change or extend the words with `Audit:ExcludePatterns` in `appsettings.json`:

```json
"Audit": { "ExcludePatterns": [ "restore", "sandbox" ] }
```

### Auditing one area at a time

Azure Resource Graph has a small per-user query quota (about 15 queries per 5 seconds). The scan uses a single paged inventory query for all resource types plus a handful of per-area queries, all serialised behind a quota-aware gate that waits and retries on HTTP 429, so even large subscriptions scan without throttling errors. If you still prefer smaller steps, untick areas on the Scope step and audit the rest later from the Grades step (**Audit this area** on a card, or **Audit remaining areas**): each area's data is merged into the same result, and the reports and improvement plan cover whatever has been audited so far.

No Azure access? Click **Try with sample data** on the home page. The whole flow then runs on a realistic built-in estate (a well-run production subscription next to a neglected dev/test one), without calling Azure.

### Authentication and permissions

> [!WARNING]
> **RateMyAzureSubscriptions has no login of its own.** Every visitor to the site uses the same Azure credential the app was started with. Run it on your own workstation, or put it behind authentication you control (App Service Easy Auth or a reverse proxy). Hosted with a managed identity and no auth in front, **anyone who can reach the URL can read every subscription and directory setting that identity has access to.**

The app uses `AzureCliCredential` by default. To run it without the Azure CLI (App Service, a container with a managed identity), set `Azure:Credential` to `Default` in `appsettings.json` or as the environment variable `Azure__Credential=Default`.

The credential needs:

- **Reader** on the subscriptions (Resource Graph, ARM reads, Defender for Cloud pricing and contacts, diagnostic settings, role assignments).
- For the **Microsoft Entra ID** area and principal resolution in IAM: Microsoft Graph read access. A user signed in with `az login` who holds **Global Reader** (or Security Reader + Directory Readers) is enough. An app or managed identity needs `Policy.Read.All`, `Directory.Read.All`, `Application.Read.All` and `RoleManagement.Read.Directory`.

Anything the credential cannot read is reported as a warning on the Grades step and rated as unknown (half points) rather than failing the scan. If Microsoft Graph is unavailable, the Entra ID area is shown as "not assessed" and the other five are still graded.

### What the scan reads

Everything is read-only, through Azure Resource Graph, ARM `GET` calls and Microsoft Graph `GET`/`getByIds`:

- VMs (power state, size, zones, disks, diagnostics, identity, licence), disks, App Services and plans, Azure Backup protected items
- Virtual networks and subnets, NSGs and rules, public IPs, NICs, private endpoints, private DNS zones, Network Watchers, flow logs, Bastion, Azure Firewall
- Storage accounts, plus blob service properties and lifecycle policies per account (first 60)
- Key Vaults, SQL servers, Log Analytics workspaces
- Defender for Cloud pricing, security contacts, secure score and assessments; Azure Policy assignments; subscription diagnostic settings
- Role assignments and definitions, user-assigned identities; app registrations' credentials
- Entra: organisation, security defaults, Conditional Access policies, authorization policy, privileged directory role members, user/guest counts, authentication methods policy

RateMyAzureSubscriptions never modifies a resource. The fix scripts it generates are Azure CLI you review and run yourself.

## Tests

```powershell
dotnet test
```

The suite covers the rating engine and all six assessors (driven by the sample estate and hand-built cases), JSON parsing of every Azure shape, graceful degradation when sources are unreadable, the three Word/HTML reports, and the Blazor components (bUnit).

## Project layout

```
src/RateMyAzureSubscriptions/
  Components/Pages       Home, AuditPage, ModelPage
  Components/Shared      AuditFlow (wizard), ScopeStep, GradesStep, PlanStep, AreaInventory, modals, badges
  Models                 Areas, Rating, Estate (inventory), Subscriptions
  Services/
    AuditRatingService   Grade bands, caps, roll-up, RatingBuilder
    Assessment/          One assessor per area + FindingCatalog (fixes, effort, scripts)
    AuditDiscoveryService  Resource Graph / ARM / Microsoft Graph discovery and parsing
    AuditReportService   Summary, detailed findings and improvement plan (docx + HTML preview)
    DemoDataService      The sample estate
tests/RateMyAzureSubscriptions.Tests    xUnit + bUnit
```
