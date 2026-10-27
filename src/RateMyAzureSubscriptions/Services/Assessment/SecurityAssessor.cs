using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Security (100): Defender for Cloud 30 · posture 20 · policy &amp; governance 15 · encryption &amp; secrets 20 · logging 15.
/// Caps: no Defender plan enabled anywhere → max C · Activity Log not exported → max B.
/// </summary>
internal static class SecurityAssessor
{
    public const string DefenderCategory = "Defender for Cloud";
    public const string PostureCategory = "Security posture";
    public const string PolicyCategory = "Policy & governance";
    public const string EncryptionCategory = "Encryption & secrets";
    public const string LoggingCategory = "Logging & monitoring";

    /// <summary>Defender plans that matter when the matching resource type exists.</summary>
    internal static IEnumerable<string> RelevantPlans(AuditScanResult scan)
    {
        if (scan.VirtualMachines.Count > 0) yield return "VirtualMachines";
        if (scan.StorageAccounts.Count > 0) yield return "StorageAccounts";
        if (scan.KeyVaults.Count > 0) yield return "KeyVaults";
        if (scan.SqlServers.Count > 0) yield return "SqlServers";
        if (scan.WebApps.Count > 0) yield return "AppServices";
        yield return "Arm";
    }

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.Security;
        var subs = scan.SubscriptionSecurity;
        if (subs.Count == 0)
            return RatingBuilder.NotAssessed(area, "No subscription security data was collected.");

        var b = new RatingBuilder(area);
        var plans = RelevantPlans(scan).ToList();

        // ── 1. Defender for Cloud (30) ───────────────────────────────────────
        var def = b.Category(DefenderCategory, 30);
        var readable = subs.Where(s => s.DefenderPlansReadable).ToList();
        if (readable.Count == 0)
        {
            def.Earned += 10;
            def.Details.Add("Defender plan state could not be read — half points awarded.");
        }
        else
        {
            var total = readable.Count * plans.Count;
            var enabled = readable.Sum(s => plans.Count(s.IsPlanEnabled));
            b.Check(def, 20, enabled, total,
                $"{enabled} of {total} relevant Defender plan(s) are enabled across {readable.Count} subscription(s).",
                $"Enable the {total - enabled} missing Defender for Cloud plan(s).", "nodefender");
            if (enabled == 0)
                b.Cap("nodefender", "C", "No Microsoft Defender for Cloud plan is enabled in any subscription.");
            foreach (var s in readable)
                foreach (var p in plans.Where(p => !s.IsPlanEnabled(p)))
                    findings.Add(area, p is "VirtualMachines" or "StorageAccounts" or "SqlServers" ? "Medium" : "Low", "Defender plan off",
                        $"Defender for Cloud plan '{p}' is not enabled.", p, $"/subscriptions/{s.SubscriptionId}/providers/Microsoft.Security/pricings/{p}", "", s.SubscriptionId);
        }

        var contactKnown = subs.Where(s => s.SecurityContactConfigured is not null).ToList();
        var contacts = contactKnown.Count(s => s.SecurityContactConfigured == true);
        b.Check(def, 5, contacts, contactKnown.Count,
            contactKnown.Count == 0 ? "Security contact state could not be read." : $"{contacts} of {contactKnown.Count} subscription(s) have a security contact configured.",
            $"Configure a security contact on {contactKnown.Count - contacts} subscription(s).");
        foreach (var s in contactKnown.Where(s => s.SecurityContactConfigured == false))
            findings.Add(area, "Medium", "No security contact", "No Defender for Cloud security contact is configured; alerts have nowhere to go.", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);

        var scored = subs.Where(s => s.SecureScorePercent is not null).ToList();
        if (scored.Count == 0)
        {
            def.Earned += 2;
            def.Details.Add("Secure score not available.");
        }
        else
        {
            var avg = scored.Average(s => s.SecureScorePercent!.Value);
            var pts = (int)Math.Round(5 * Math.Clamp(avg / 100.0, 0, 1));
            def.Earned += pts;
            def.Details.Add($"Average secure score {avg:0}%.");
            if (pts < 5) b.Improve($"Raise the secure score (currently {avg:0}%) by remediating Defender for Cloud recommendations.", 5 - pts);
            foreach (var s in scored.Where(s => s.SecureScorePercent < 60))
                findings.Add(area, "Medium", "Low secure score", $"Secure score is {s.SecureScorePercent:0}%.", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);
        }

        // ── 2. Security posture (20) ─────────────────────────────────────────
        var posture = b.Category(PostureCategory, 20);
        var assessed = subs.Where(s => s.AssessmentsAvailable).ToList();
        if (assessed.Count == 0)
        {
            posture.Earned = 10;
            posture.Details.Add("Defender for Cloud assessments not available — half points awarded.");
        }
        else
        {
            var healthy = assessed.Sum(s => s.HealthyAssessments);
            var total = assessed.Sum(s => s.HealthyAssessments + s.UnhealthyAssessments);
            var highSev = assessed.Sum(s => s.HighSeverityUnhealthy);
            b.Check(posture, 20, healthy, total,
                $"{healthy} of {total} Defender recommendations are healthy; {highSev} unhealthy High severity.",
                $"Remediate the {total - healthy} unhealthy Defender for Cloud recommendations ({highSev} High severity first).");
            foreach (var s in assessed.Where(s => s.HighSeverityUnhealthy > 0))
                findings.Add(area, "Medium", "Unhealthy recommendations", $"{s.HighSeverityUnhealthy} High severity Defender for Cloud recommendation(s) are unhealthy ({s.UnhealthyAssessments} unhealthy in total).", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);
        }

        // ── 3. Policy & governance (15) ──────────────────────────────────────
        var pol = b.Category(PolicyCategory, 15);
        var mcsb = subs.Count(s => s.HasSecurityBenchmarkAssignment);
        b.Check(pol, 8, mcsb, subs.Count,
            $"The Microsoft cloud security benchmark is assigned in {mcsb} of {subs.Count} subscription(s).",
            $"Assign the Microsoft cloud security benchmark in {subs.Count - mcsb} subscription(s).");
        foreach (var s in subs.Where(s => !s.HasSecurityBenchmarkAssignment))
            findings.Add(area, "Medium", "Security benchmark not assigned", "The Microsoft cloud security benchmark initiative is not assigned, so regulatory compliance is not measured.", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);

        var withPolicies = subs.Count(s => s.PolicyAssignmentCount > 0);
        b.Check(pol, 7, withPolicies, subs.Count,
            $"{withPolicies} of {subs.Count} subscription(s) have Azure Policy assignments ({subs.Sum(s => s.PolicyAssignmentCount)} in total).",
            $"Assign guardrail policies in the {subs.Count - withPolicies} subscription(s) without any.");
        foreach (var s in subs.Where(s => s.PolicyAssignmentCount == 0))
            findings.Add(area, "Low", "No policy assignments", "No Azure Policy assignment applies to this subscription.", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);

        // ── 4. Encryption & secrets (20) ─────────────────────────────────────
        var enc = b.Category(EncryptionCategory, 20);
        var kvs = scan.KeyVaults;
        b.Check(enc, 5, kvs.Count(k => k.SoftDeleteEnabled), kvs.Count,
            kvs.Count == 0 ? "No Key Vaults to assess." : $"{kvs.Count(k => k.SoftDeleteEnabled)} of {kvs.Count} Key Vault(s) have soft delete.",
            "Enable soft delete on every Key Vault.");
        foreach (var k in kvs.Where(k => !k.SoftDeleteEnabled))
            findings.Add(area, "High", "Key Vault soft delete off", $"Key Vault '{k.Name}' has soft delete disabled.", k);

        b.Check(enc, 5, kvs.Count(k => k.PurgeProtectionEnabled), kvs.Count,
            kvs.Count == 0 ? "No Key Vaults to assess." : $"{kvs.Count(k => k.PurgeProtectionEnabled)} of {kvs.Count} Key Vault(s) have purge protection.",
            "Enable purge protection on every Key Vault.");
        foreach (var k in kvs.Where(k => !k.PurgeProtectionEnabled))
            findings.Add(area, "Medium", "Key Vault purge protection off", $"Key Vault '{k.Name}' has no purge protection.", k);

        b.Check(enc, 4, kvs.Count(k => k.RbacAuthorization), kvs.Count,
            kvs.Count == 0 ? "No Key Vaults to assess." : $"{kvs.Count(k => k.RbacAuthorization)} of {kvs.Count} Key Vault(s) use the RBAC permission model.",
            "Migrate Key Vaults from access policies to Azure RBAC.");
        foreach (var k in kvs.Where(k => !k.RbacAuthorization))
            findings.Add(area, "Low", "Key Vault access policies", $"Key Vault '{k.Name}' uses the legacy access-policy permission model.", k);

        b.Check(enc, 3, kvs.Count(k => k.PublicNetworkRestricted), kvs.Count,
            kvs.Count == 0 ? "No Key Vaults to assess." : $"{kvs.Count(k => k.PublicNetworkRestricted)} of {kvs.Count} Key Vault(s) restrict public network access.",
            "Restrict public network access on Key Vaults.");
        foreach (var k in kvs.Where(k => !k.PublicNetworkRestricted))
            findings.Add(area, "Medium", "Key Vault public access", $"Key Vault '{k.Name}' accepts connections from any network.", k);

        var sql = scan.SqlServers;
        var sqlOk = sql.Count(q => q.TlsOk && q.EntraOnlyAuthentication);
        b.Check(enc, 3, sqlOk, sql.Count,
            sql.Count == 0 ? "No SQL servers to assess." : $"{sqlOk} of {sql.Count} SQL server(s) require TLS 1.2 and Entra-only authentication.",
            "Require TLS 1.2 and Entra-only authentication on SQL servers.");
        foreach (var q in sql.Where(q => !q.TlsOk))
            findings.Add(area, "Medium", "Outdated TLS on SQL", $"SQL server '{q.Name}' allows TLS {(string.IsNullOrEmpty(q.MinimalTlsVersion) ? "1.0" : q.MinimalTlsVersion)}.", q);
        foreach (var q in sql.Where(q => !q.EntraOnlyAuthentication))
            findings.Add(area, "Low", "SQL not Entra-only", $"SQL server '{q.Name}' still allows SQL authentication{(q.HasEntraAdmin ? "" : " and has no Entra administrator")}.", q);
        foreach (var q in sql.Where(q => !q.PublicNetworkRestricted))
            findings.Add(area, "Medium", "SQL public access", $"SQL server '{q.Name}' has public network access enabled.", q);

        // ── 5. Logging & monitoring (15) ─────────────────────────────────────
        var log = b.Category(LoggingCategory, 15);
        var exportKnown = subs.Where(s => s.ActivityLogExported is not null).ToList();
        if (exportKnown.Count == 0)
        {
            log.Earned += 5;
            log.Details.Add("Activity Log export state could not be read — half points awarded.");
        }
        else
        {
            var exported = exportKnown.Count(s => s.ActivityLogExported == true);
            b.Check(log, 9, exported, exportKnown.Count,
                $"The Activity Log is exported in {exported} of {exportKnown.Count} subscription(s).",
                $"Export the Activity Log to Log Analytics in {exportKnown.Count - exported} subscription(s).", "noactivity");
            if (exported < exportKnown.Count)
                b.Cap("noactivity", "B", "The Activity Log is not exported in every subscription, so changes are lost after 90 days.");
            foreach (var s in exportKnown.Where(s => s.ActivityLogExported == false))
                findings.Add(area, "Medium", "Activity log not exported", "The subscription Activity Log is not sent to a Log Analytics workspace.", "Subscription", $"/subscriptions/{s.SubscriptionId}", "", s.SubscriptionId);
        }

        var withLaw = subs.Count(s => s.LogAnalyticsWorkspaceCount > 0);
        var anyLaw = subs.Any(s => s.LogAnalyticsWorkspaceCount > 0);
        if (anyLaw)
        {
            log.Earned += 6;
            log.Details.Add($"{subs.Sum(s => s.LogAnalyticsWorkspaceCount)} Log Analytics workspace(s) across the scanned subscriptions.");
        }
        else
        {
            log.Details.Add("No Log Analytics workspace in any scanned subscription.");
            b.Improve("Create a central Log Analytics workspace for diagnostics, the Activity Log and Defender.", 6);
            findings.Add(area, "Low", "No Log Analytics workspace", "No Log Analytics workspace exists in the scanned subscriptions.", "Subscriptions in scope");
        }

        var parts = new List<string> { $"{subs.Count} subscription{(subs.Count == 1 ? "" : "s")}" };
        if (kvs.Count > 0) parts.Add($"{kvs.Count} Key Vault{(kvs.Count == 1 ? "" : "s")}");
        if (sql.Count > 0) parts.Add($"{sql.Count} SQL server{(sql.Count == 1 ? "" : "s")}");
        return b.Build(subs.Count + kvs.Count + sql.Count, string.Join(", ", parts));
    }
}
