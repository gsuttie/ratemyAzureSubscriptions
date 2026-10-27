using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services.Reports;

namespace RateMyAzureSubscriptions.Services;

/// <summary>Everything the reports need that isn't in the scan result itself.</summary>
public sealed class AuditReportContext
{
    public string CustomerName { get; init; } = "";
    public string TenantName { get; init; } = "";
    public string ReportAuthor { get; init; } = "";
    public DateTime ScanDate { get; init; } = DateTime.Now;
    public List<string> SubscriptionLines { get; init; } = new();
    public Dictionary<string, string> SubscriptionNames { get; init; } = new(StringComparer.OrdinalIgnoreCase);
    public AuditScanResult? Scan { get; init; }

    /// <summary>Severities to include; the same choice as the checkboxes in the app. Null or all three = unfiltered.</summary>
    public IReadOnlySet<string>? VisibleSeverities { get; init; }

    public string SubName(string id) => SubscriptionNames.TryGetValue(id, out var n) ? n : id;

    public bool IsFiltered => VisibleSeverities is not null && VisibleSeverities.Count < 3;
    public IEnumerable<AuditFinding> Visible(IEnumerable<AuditFinding> findings) =>
        VisibleSeverities is null ? findings : findings.Where(f => VisibleSeverities.Contains(f.Severity));
    public List<AuditFinding> Findings => Visible(Scan?.Findings ?? []).ToList();
    public List<AuditFinding> FindingsFor(AuditArea area) => Visible(Scan?.FindingsFor(area) ?? []).ToList();
    public string SeverityScope => IsFiltered
        ? string.Join(", ", new[] { "High", "Medium", "Low" }.Where(s => VisibleSeverities!.Contains(s))) + " (" +
          string.Join(", ", new[] { "High", "Medium", "Low" }.Where(s => !VisibleSeverities!.Contains(s))) + " hidden by the severity filter)"
        : "High, Medium and Low";
}

public enum ReportKind { Summary, Findings, Plan }

/// <summary>Builds the summary, detailed-findings and improvement-plan reports (as a ReportDoc).</summary>
public static class AuditReportService
{
    public static byte[] Docx(AuditReportContext ctx, ReportKind kind) => DocxReportRenderer.Render(Build(ctx, kind));
    public static string Html(AuditReportContext ctx, ReportKind kind) => HtmlReportRenderer.Render(Build(ctx, kind));
    public static string Markdown(AuditReportContext ctx, ReportKind kind) => MarkdownReportRenderer.Render(Build(ctx, kind));

    public static ReportDoc Build(AuditReportContext ctx, ReportKind kind) => kind switch
    {
        ReportKind.Findings => BuildFindings(ctx),
        ReportKind.Plan => BuildPlan(ctx),
        _ => BuildSummary(ctx),
    };

    public static string FileName(AuditReportContext ctx, ReportKind kind)
    {
        var customer = string.Concat((ctx.CustomerName ?? "").Where(c => char.IsLetterOrDigit(c) || c is '-' or '_'));
        if (string.IsNullOrEmpty(customer)) customer = "Azure";
        var suffix = kind switch { ReportKind.Findings => "Findings", ReportKind.Plan => "ImprovementPlan", _ => "Summary" };
        return $"{customer}-AzureAudit-{suffix}-{ctx.ScanDate:yyyyMMdd}.docx";
    }

    public static string Title(ReportKind kind) => kind switch
    {
        ReportKind.Findings => "Detailed findings",
        ReportKind.Plan => "Improvement plan",
        _ => "Summary report",
    };

    // ── Summary report ───────────────────────────────────────────────────────

    public static ReportDoc BuildSummary(AuditReportContext ctx)
    {
        var scan = ctx.Scan;
        List<AuditFinding> findings = ctx.Findings;
        var doc = new ReportDoc { Title = "Azure Environment Audit - Summary Report" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1("2. Purpose and scope");
        doc.P("This audit assesses the current configuration of the Azure environment, identifies potential risks, and highlights areas requiring attention, improvement or optimisation. " +
              "The environment is reviewed against Microsoft Azure best practices, focusing on security, governance, performance, reliability and cost optimisation.");
        doc.P("The findings are documented here and feed a prioritised improvement plan, with recommendations based on business requirements, operational impact and Microsoft guidance. " +
              "Six areas are scored individually: Compute, Networking, Security, Storage, Microsoft Entra ID, and Identity and Access Management.");
        doc.Note("This report is the output of a read-only scan; no changes were made to any Azure resource.");

        doc.H1("3. Executive summary");
        if (scan is null)
        {
            doc.P("No scan data was available when this report was generated - run a scan to populate the sections below.");
        }
        else
        {
            var high = findings.Count(f => f.Severity == "High");
            var medium = findings.Count(f => f.Severity == "Medium");
            var low = findings.Count(f => f.Severity == "Low");
            var assessed = scan.Ratings.Where(r => !r.NotAssessed).ToList();
            doc.P($"The scan covered {ctx.SubscriptionLines.Count} subscription(s) and {scan.TotalResources} resources across {assessed.Count} assessed area(s). " +
                  $"It produced {findings.Count} finding(s): {high} High, {medium} Medium and {low} Low.");
            var worst = AuditRatingService.Worst(scan.Ratings);
            if (worst is not null)
                doc.P($"The weakest area is {worst.Area.Label()} (grade {worst.Grade}, {worst.Score}/100){(worst.CapReason is null ? "" : $": {worst.CapReason}")}. " +
                      $"The strongest is {assessed.OrderBy(r => r.Grade, StringComparer.Ordinal).ThenByDescending(r => r.Score).First().Area.Label()}.");
            var topHigh = findings.Where(f => f.Severity == "High").GroupBy(f => f.Category).OrderByDescending(g => g.Count()).Take(3).Select(g => $"{g.Key.ToLowerInvariant()} ({g.Count()})").ToList();
            if (topHigh.Count > 0) doc.P($"The most frequent High severity issues: {string.Join("; ", topHigh)}.");
        }

        doc.H1("4. Overall rating");
        OverallSection(doc, ctx);

        doc.H1("5. Area ratings");
        AreaTable(doc, ctx);
        foreach (var r in scan?.Ratings ?? [])
        {
            doc.H2($"5.{(int)r.Area + 1} {r.Area.Label()}");
            AreaDetail(doc, r, brief: true);
        }

        doc.H1("6. Estate overview");
        doc.Table(["Metric", "Value"], InventoryRows(ctx), "No scan data available.");

        doc.H1("7. Findings summary");
        doc.Table(["Priority", "Area", "Category", "Finding", "Resource"],
            findings.Select(f => new[] { $"P{f.Priority} · {f.Severity}", f.Area.ShortLabel(), f.Category, f.Message, f.ResourceName }).ToList(),
            scan is null ? "No scan data available." : "No findings - the environment matches every check performed.",
            findings.Select(f => new string?[] { SeverityColor(f.Severity), null, null, null, null }).ToList());

        doc.H1("8. Recommendations");
        var recs = new List<string>();
        foreach (var r in (scan?.Ratings ?? []).Where(r => !r.NotAssessed).OrderByDescending(r => r.Grade, StringComparer.Ordinal).ThenBy(r => r.Score))
            foreach (var i in r.Improvements.Take(2))
                recs.Add($"{r.Area.ShortLabel()}: {i.Action} (+{i.PointsGained} pts)");
        if (recs.Count == 0) recs.Add("No immediate actions required - continue periodic scans to maintain the current posture.");
        doc.Bullets(recs.Take(12));
        doc.Note("All recommendations are advisory. RateMyAzureSubscriptions does not modify any Azure or Microsoft Entra configuration.");

        return doc;
    }

    // ── Detailed findings report ─────────────────────────────────────────────

    public static ReportDoc BuildFindings(AuditReportContext ctx)
    {
        var scan = ctx.Scan;
        var doc = new ReportDoc { Title = "Azure Environment Audit - Detailed Findings" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        doc.H1("2. Overall rating");
        OverallSection(doc, ctx);
        AreaTable(doc, ctx);

        var n = 3;
        foreach (var area in AuditAreaExtensions.All)
        {
            var r = scan?.Rating(area);
            doc.H1($"{n}. {area.Label()}");
            doc.P(area.Description());
            if (r is null) { doc.P("No scan data available."); n++; continue; }

            doc.H2($"{n}.1 Rating");
            AreaDetail(doc, r, brief: false);

            doc.H2($"{n}.2 Findings");
            var fs = ctx.FindingsFor(area);
            if (fs.Count == 0) doc.P(r.NotAssessed ? "Not assessed." : "No findings in this area.");
            else
                foreach (var group in fs.GroupBy(f => f.Severity).OrderBy(g => AuditRatingService.SeverityOrder(g.Key)))
                {
                    doc.P($"{group.Key} ({group.Count()})", bold: true, color: SeverityColor(group.Key));
                    doc.Bullets(group.Select(f => $"{f.Category}: {f.Message} - {f.ResourceName} [{ctx.SubName(f.SubscriptionId)}]. Fix ({f.Effort.ToLowerInvariant()} effort): {f.Fix}"));
                }

            doc.H2($"{n}.3 Inventory");
            InventoryFor(doc, scan!, area, ctx);
            n++;
        }

        return doc;
    }

    // ── Improvement plan ─────────────────────────────────────────────────────

    public static ReportDoc BuildPlan(AuditReportContext ctx)
    {
        var scan = ctx.Scan;
        List<AuditFinding> findings = ctx.Findings;
        var doc = new ReportDoc { Title = "Azure Environment Audit - Prioritised Improvement Plan" };

        doc.H1("1. Document information");
        DocInfo(doc, ctx);

        if (scan is null)
            doc.P("No scan data was available when this report was generated - run a scan to populate the plan.");

        doc.H1("2. How to read this plan");
        doc.P("Every finding from the audit is listed once, grouped into three priorities. Priority 1 items carry High severity (an exposure or a missing safeguard that should be addressed first); " +
              "Priority 2 items are Medium (hardening and resilience gaps to schedule into the next change windows); Priority 3 items are Low (hygiene and cost optimisation). " +
              "Within a priority, items with low effort are listed first so quick wins can be taken early. Effort is an indicative size for the change itself, not a time estimate.");
        doc.P("Each action is advisory and should be validated against business requirements and operational impact before being implemented. Where a fix script is shown in the application it is a starting point to review, not something to run blindly.");

        doc.H1("3. Plan at a glance");
        doc.Table(["Priority", "Items", "Low effort", "Medium effort", "High effort"],
            new[] { 1, 2, 3 }.Select(p =>
            {
                var items = findings.Where(f => f.Priority == p).ToList();
                return new[] { $"P{p}", items.Count.ToString(), items.Count(f => f.Effort == "Low").ToString(), items.Count(f => f.Effort == "Medium").ToString(), items.Count(f => f.Effort == "High").ToString() };
            }).ToList(), "No scan data available.");

        var n = 4;
        foreach (var p in new[] { 1, 2, 3 })
        {
            var items = findings.Where(f => f.Priority == p).OrderBy(f => AuditRatingService.EffortOrder(f.Effort)).ThenBy(f => f.Area).ThenBy(f => f.Category).ToList();
            doc.H1($"{n}. Priority {p} - {PriorityLabel(p)}");
            if (items.Count == 0) { doc.P("Nothing at this priority."); n++; continue; }

            foreach (var group in items.GroupBy(f => (f.Area, f.Category)))
            {
                var first = group.First();
                doc.P($"{first.Area.ShortLabel()} · {first.Category} ({group.Count()}) · {first.Effort} effort", bold: true, color: SeverityColor(first.Severity));
                doc.P(first.Fix);
                doc.Bullets(group.Select(f => $"{f.ResourceName} [{ctx.SubName(f.SubscriptionId)}]: {f.Message}"));
            }
            n++;
        }

        doc.H1($"{n}. Expected effect on the grades");
        var any = false;
        foreach (var r in (scan?.Ratings ?? []).Where(r => !r.NotAssessed && r.Improvements.Count > 0).OrderByDescending(r => r.Grade, StringComparer.Ordinal))
        {
            any = true;
            doc.P($"{r.Area.Label()} - grade {r.Grade}, {r.Score}/100", bold: true, color: AuditRatingService.ColorForGrade(r.Grade));
            doc.Bullets(r.Improvements.Select(i => $"+{i.PointsGained} pts - {i.Action}" +
                (AuditRatingService.WorstGrade(i.ResultingGrade, r.Grade) != i.ResultingGrade ? $" (raises the grade to {i.ResultingGrade})" : "")));
        }
        if (!any) doc.P("Every assessed area already earns full marks.");

        return doc;
    }

    // ── Shared sections ──────────────────────────────────────────────────────

    public static string PriorityLabel(int p) => p switch { 1 => "Fix first", 2 => "Fix soon", _ => "Worth doing" };

    private static void DocInfo(ReportDoc doc, AuditReportContext ctx) =>
        doc.Table(null,
        [
            ["Customer", Fallback(ctx.CustomerName, "Unknown")],
            ["Prepared by", Fallback(ctx.ReportAuthor, "RateMyAzureSubscriptions")],
            ["Scan date", ctx.ScanDate.ToString("yyyy-MM-dd HH:mm")],
            ["Tenant", Fallback(ctx.TenantName, "Unknown")],
            ["Subscriptions in scope", ctx.SubscriptionLines.Count > 0 ? string.Join("\n", ctx.SubscriptionLines) : "None"],
            ["Findings included", ctx.SeverityScope],
            ["Generated by", "RateMyAzureSubscriptions - Azure environment audit (read-only)"],
        ], "", firstColHeader: true);

    private static void OverallSection(ReportDoc doc, AuditReportContext ctx)
    {
        var scan = ctx.Scan;
        if (scan is null || scan.Ratings.All(r => r.NotAssessed))
        {
            doc.P(scan is null ? "No scan data available." : "Nothing could be assessed in the scanned subscriptions.");
            doc.Legend();
            return;
        }
        var grade = AuditRatingService.OverallGrade(scan);
        var worst = AuditRatingService.Worst(scan.Ratings)!;
        doc.Grade(grade, AuditRatingService.LabelForGrade(grade),
            $"Average {scan.OverallScore}/100 across {scan.Ratings.Count(r => !r.NotAssessed)} assessed area(s); the weakest area is {worst.Area.Label()} ({worst.Grade}, {worst.Score}/100). " +
            "The overall grade is never more than one band above the weakest area.");
        doc.P("Scoring model: each area is scored on its own 100-point scale from weighted categories. Grade bands: A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 45, E ≥ 30, F < 30. Hard caps stop a good score hiding a critical gap (for example management ports open to the Internet cap Networking at D).");
        doc.Legend();
    }

    private static void AreaTable(ReportDoc doc, AuditReportContext ctx)
    {
        var ratings = ctx.Scan?.Ratings ?? [];
        var rows = new List<string[]>();
        var colors = new List<string?[]>();
        foreach (var r in ratings)
        {
            rows.Add([r.Area.Label(), r.NotAssessed ? "Not assessed" : $"{r.Grade} - {r.GradeLabel}", r.NotAssessed ? "-" : $"{r.Score}/100", r.NotAssessed ? r.NotAssessedReason ?? "" : r.CapReason ?? r.Improvements.FirstOrDefault()?.Action ?? "No gaps identified."]);
            var c = AuditRatingService.ColorForGrade(r.Grade);
            colors.Add([null, c, c, null]);
        }
        doc.Table(["Area", "Grade", "Score", "Biggest gap"], rows, "No scan data available.", colors);
    }

    private static void AreaDetail(ReportDoc doc, AreaRating r, bool brief)
    {
        if (r.Issues.Count > 0)
        {
            doc.P($"{r.Issues.Count} data source(s) could not be read, so this grade is based on partial data:", bold: true, color: "#F57C00");
            doc.Bullets(r.Issues.Select(i => $"{i.Source}: {i.Reason}. {i.Impact} Needs {i.Needs}. Fix: {i.Fix}"));
        }
        if (r.NotAssessed)
        {
            doc.P($"Not assessed: {r.NotAssessedReason}");
            return;
        }
        doc.Grade(r.Grade, r.GradeLabel, $"{r.Score}/100 - {r.ScopeSummary}.{(r.CapReason is null ? "" : $" Grade capped: {r.CapReason}")}");
        doc.Table(["Category", "Score", "Detail"],
            r.Categories.Select(c => new[] { c.Name, $"{c.Earned}/{c.Possible}", string.Join(" ", c.Details) }).ToList(), "");
        if (r.Improvements.Count == 0) doc.P("Nothing to improve - full marks.");
        else
            doc.Bullets((brief ? r.Improvements.Take(4) : r.Improvements).Select(i => $"+{i.PointsGained} pts - {i.Action}" +
                (AuditRatingService.WorstGrade(i.ResultingGrade, r.Grade) != i.ResultingGrade ? $" (raises the grade to {i.ResultingGrade})" : "")));
    }

    private static List<string[]> InventoryRows(AuditReportContext ctx)
    {
        var s = ctx.Scan;
        if (s is null) return [];
        return
        [
            ["Subscriptions", s.SubscriptionIds.Count.ToString()],
            ["Virtual machines", s.VirtualMachines.Count.ToString()],
            ["App Services / Function Apps", s.WebApps.Count.ToString()],
            ["App Service plans", s.AppServicePlans.Count.ToString()],
            ["Managed disks (unattached)", $"{s.Disks.Count} ({s.Disks.Count(d => d.IsUnattached)})"],
            ["Virtual networks / subnets", $"{s.VirtualNetworks.Count} / {s.VirtualNetworks.Sum(v => v.Subnets.Count)}"],
            ["Network security groups", s.NetworkSecurityGroups.Count.ToString()],
            ["Public IP addresses (unattached)", $"{s.PublicIps.Count} ({s.PublicIps.Count(p => !p.IsAttached)})"],
            ["Private endpoints", s.PrivateEndpoints.Count.ToString()],
            ["Storage accounts", s.StorageAccounts.Count.ToString()],
            ["Key Vaults", s.KeyVaults.Count.ToString()],
            ["SQL servers", s.SqlServers.Count.ToString()],
            ["Role assignments / custom roles", $"{s.Iam.RoleAssignments.Count} / {s.Iam.CustomRoles.Count}"],
            ["Conditional Access policies", s.Entra.IsAssessable ? s.Entra.ConditionalAccessPolicies.Count.ToString() : "not read"],
            ["Total findings", ctx.Findings.Count.ToString()],
        ];
    }

    private static void InventoryFor(ReportDoc doc, AuditScanResult s, AuditArea area, AuditReportContext ctx)
    {
        switch (area)
        {
            case AuditArea.Compute:
                doc.Table(["VM", "Size", "State", "Zone/set", "Backup", "Managed disks", "Subscription"],
                    s.VirtualMachines.OrderBy(v => v.Name).Select(v => new[] { v.Name, v.Size, Fallback(v.PowerState, "unknown"), v.IsZonalOrInSet ? "yes" : "no", v.IsBackedUp switch { true => "yes", false => "no", null => "unknown" }, v.UsesManagedDisks ? "yes" : "no", ctx.SubName(v.SubscriptionId) }).ToList(), "No virtual machines.");
                doc.Table(["App", "Type", "HTTPS only", "Min TLS", "FTP", "Identity", "Subscription"],
                    s.WebApps.OrderBy(a => a.Name).Select(a => new[] { a.Name, a.TypeLabel, a.HttpsOnly ? "yes" : "no", Fallback(a.MinTlsVersion, "default"), Fallback(a.FtpsState, "default"), a.HasManagedIdentity ? "yes" : "no", ctx.SubName(a.SubscriptionId) }).ToList(), "No App Services.");
                doc.Table(["Plan", "SKU", "Instances", "Apps", "Subscription"],
                    s.AppServicePlans.OrderBy(p => p.Name).Select(p => new[] { p.Name, p.SkuName, p.Capacity.ToString(), p.NumberOfSites.ToString(), ctx.SubName(p.SubscriptionId) }).ToList(), "No App Service plans.");
                break;
            case AuditArea.Networking:
                doc.Table(["Virtual network", "Address space", "Subnets (with NSG)", "DDoS", "Subscription"],
                    s.VirtualNetworks.OrderBy(v => v.Name).Select(v => new[] { v.Name, string.Join(", ", v.AddressSpaces), $"{v.Subnets.Count} ({v.Subnets.Count(x => x.NsgId is not null)})", v.DdosProtectionEnabled ? "yes" : "no", ctx.SubName(v.SubscriptionId) }).ToList(), "No virtual networks.");
                doc.Table(["NSG", "Rules", "Risky rules", "Associated", "Subscription"],
                    s.NetworkSecurityGroups.OrderBy(n => n.Name).Select(n => new[] { n.Name, n.Rules.Count.ToString(), n.RiskyRules.Count.ToString(), n.IsOrphaned ? "no" : $"{n.SubnetCount} subnet(s), {n.NicCount} NIC(s)", ctx.SubName(n.SubscriptionId) }).ToList(), "No network security groups.");
                doc.Table(["Public IP", "Address", "SKU", "Attached", "Subscription"],
                    s.PublicIps.OrderBy(p => p.Name).Select(p => new[] { p.Name, Fallback(p.IpAddress, "-"), p.Sku, p.IsAttached ? "yes" : "no", ctx.SubName(p.SubscriptionId) }).ToList(), "No public IP addresses.");
                break;
            case AuditArea.Security:
                doc.Table(["Subscription", "Defender plans on", "Secure score", "Security contact", "Activity Log export", "Policy assignments"],
                    s.SubscriptionSecurity.Select(x => new[] { ctx.SubName(x.SubscriptionId), x.DefenderPlansReadable ? $"{x.EnabledPlanCount} of {x.DefenderPlans.Count}" : "unknown", x.SecureScorePercent is { } p ? $"{p:0}%" : "unknown", x.SecurityContactConfigured switch { true => "yes", false => "no", null => "unknown" }, x.ActivityLogExported switch { true => string.Join(", ", x.ActivityLogDestinations), false => "no", null => "unknown" }, x.PolicyAssignmentCount.ToString() }).ToList(), "No subscription data.");
                doc.Table(["Key Vault", "Soft delete", "Purge protection", "RBAC", "Public access", "Subscription"],
                    s.KeyVaults.OrderBy(k => k.Name).Select(k => new[] { k.Name, k.SoftDeleteEnabled ? "yes" : "no", k.PurgeProtectionEnabled ? "yes" : "no", k.RbacAuthorization ? "yes" : "access policies", k.PublicNetworkRestricted ? "restricted" : "open", ctx.SubName(k.SubscriptionId) }).ToList(), "No Key Vaults.");
                doc.Table(["SQL server", "Min TLS", "Public access", "Entra-only auth", "Subscription"],
                    s.SqlServers.OrderBy(q => q.Name).Select(q => new[] { q.Name, Fallback(q.MinimalTlsVersion, "default"), q.PublicNetworkRestricted ? "disabled" : "enabled", q.EntraOnlyAuthentication ? "yes" : "no", ctx.SubName(q.SubscriptionId) }).ToList(), "No SQL servers.");
                break;
            case AuditArea.Storage:
                doc.Table(["Account", "Kind / redundancy", "Public blob", "HTTPS / TLS", "Network", "Soft delete", "Lifecycle", "Subscription"],
                    s.StorageAccounts.OrderBy(a => a.Name).Select(a => new[] { a.Name, $"{a.Kind} / {a.RedundancyLabel}", a.AllowBlobPublicAccess == false ? "disallowed" : "allowed", $"{(a.SupportsHttpsTrafficOnly ? "HTTPS" : "HTTP ok")} / {Fallback(a.MinimumTlsVersion, "TLS1_0").Replace('_', '.')}", a.PublicNetworkRestricted ? "restricted" : "all networks", a.BlobSoftDeleteEnabled switch { true => $"{a.BlobSoftDeleteDays} days", false => "off", null => "unknown" }, a.HasLifecyclePolicy switch { true => "yes", false => "no", null => "unknown" }, ctx.SubName(a.SubscriptionId) }).ToList(), "No storage accounts.");
                break;
            case AuditArea.EntraId:
                if (!s.Entra.IsAssessable) { doc.P(s.Entra.NotReadReason); break; }
                doc.Table(["Setting", "Value"],
                [
                    ["Tenant", $"{s.Entra.DisplayName} ({s.Entra.DefaultDomain})"],
                    ["Security defaults", s.Entra.SecurityDefaultsEnabled switch { true => "enabled", false => "disabled", null => "unknown" }],
                    ["Users / guests", $"{s.Entra.UserCount?.ToString() ?? "?"} / {s.Entra.GuestCount?.ToString() ?? "?"}"],
                    ["Global Administrators", s.Entra.RolesReadable ? $"{s.Entra.GlobalAdminCount}: {string.Join(", ", s.Entra.GlobalAdminNames)}" : "not read"],
                    ["Guest invitations", Fallback(s.Entra.AllowInvitesFrom, "not read")],
                    ["Guest access", s.Entra.GuestAccessRestricted ? "restricted" : "same as members"],
                    ["Users can register apps", s.Entra.UsersCanRegisterApps switch { true => "yes", false => "no", null => "not read" }],
                    ["User consent", s.Entra.UserConsentAllowed switch { true => "allowed", false => "restricted", null => "not read" }],
                ], "");
                doc.Table(["Conditional Access policy", "State", "Summary"],
                    s.Entra.ConditionalAccessPolicies.Select(p => new[] { p.Name, p.State, p.Summary }).ToList(), "No Conditional Access policies.");
                break;
            case AuditArea.Iam:
                doc.Table(["Principal", "Type", "Role", "Scope", "Subscription"],
                    s.Iam.RoleAssignments.Where(a => a.IsPrivileged || a.IsOrphaned == true || a.IsGuest == true).OrderBy(a => a.RoleName).ThenBy(a => a.Display)
                        .Select(a => new[] { a.Display + (a.IsGuest == true ? " (guest)" : "") + (a.IsOrphaned == true ? " (deleted)" : ""), Fallback(a.PrincipalType, "unknown"), a.RoleName, a.ScopeLevel, ctx.SubName(a.SubscriptionId) }).ToList(), "No privileged, orphaned or guest role assignments.");
                doc.Table(["Custom role", "Actions", "Wildcard", "Subscription"],
                    s.Iam.CustomRoles.Select(c => new[] { c.Name, string.Join(", ", c.Actions.Take(4)) + (c.Actions.Count > 4 ? ", …" : ""), c.HasWildcardActions ? "yes" : "no", ctx.SubName(c.SubscriptionId) }).ToList(), "No custom roles.");
                break;
        }
    }

    private static string Fallback(string value, string fallback) => string.IsNullOrWhiteSpace(value) ? fallback : value;

    public static string SeverityColor(string severity) => severity switch
    {
        "High" => "#D32F2F",
        "Medium" => "#F57C00",
        _ => "#1976D2"
    };
}
