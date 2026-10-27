using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services.Assessment;

/// <summary>
/// Identity and Access Management (100): least privilege 30 · group-based access 15 · workload identities 25 ·
/// hygiene 15 · scope discipline 15.
/// Caps: more than five Owners at subscription scope → max C · custom role with wildcard actions → max B.
/// </summary>
internal static class IamAssessor
{
    public const string LeastPrivilegeCategory = "Least privilege";
    public const string GroupsCategory = "Group-based access";
    public const string WorkloadCategory = "Workload identities";
    public const string HygieneCategory = "Assignment hygiene";
    public const string ScopeCategory = "Scope discipline";

    public static AreaRating Assess(AuditScanResult scan, FindingSink findings)
    {
        var area = AuditArea.Iam;
        var iam = scan.Iam;
        var ras = iam.RoleAssignments;
        if (ras.Count == 0 && iam.CustomRoles.Count == 0)
            return RatingBuilder.NotAssessed(area, "No role assignments could be read in the scanned subscriptions.");

        var b = new RatingBuilder(area);
        string SubRef(string subId) => $"/subscriptions/{subId}";

        // ── 1. Least privilege (30) ──────────────────────────────────────────
        var lp = b.Category(LeastPrivilegeCategory, 30);
        var bySub = ras.GroupBy(r => r.SubscriptionId, StringComparer.OrdinalIgnoreCase).ToList();
        var ownersOk = 0;
        foreach (var g in bySub)
        {
            var owners = g.Where(r => r.IsOwner && r.IsSubscriptionOrAbove).ToList();
            if (owners.Count <= 3) ownersOk++;
            else
                findings.Add(area, "Medium", "Too many Owners at subscription scope",
                    $"{owners.Count} principals hold Owner at subscription scope or above: {string.Join(", ", owners.Take(6).Select(o => o.Display))}{(owners.Count > 6 ? ", …" : "")}.",
                    "Subscription", SubRef(g.Key), "", g.Key);
            if (owners.Count > 5)
                b.Cap("owners", "C", $"More than five Owners at subscription scope ({owners.Count}).");
        }
        b.Check(lp, 10, ownersOk, bySub.Count,
            $"{ownersOk} of {bySub.Count} subscription(s) have three or fewer Owners at subscription scope.",
            "Reduce subscription-scope Owners to three or fewer (use a PIM-eligible group).", "owners");

        var privileged = ras.Where(r => r.IsPrivileged).ToList();
        var privToGroups = privileged.Count(r => !r.IsUser);
        b.Check(lp, 10, privToGroups, privileged.Count,
            privileged.Count == 0 ? "No privileged (Owner/Contributor/UAA) assignments." : $"{privToGroups} of {privileged.Count} privileged assignment(s) go to groups or workload identities rather than individual users.",
            $"Move the {privileged.Count - privToGroups} privileged assignment(s) on individual users to groups.");
        foreach (var g in privileged.Where(r => r.IsUser).GroupBy(r => r.SubscriptionId))
            findings.Add(area, "Medium", "Privileged role assigned to user",
                $"{g.Count()} privileged role assignment(s) are made directly to users: {string.Join(", ", g.Take(5).Select(r => $"{r.Display} ({r.RoleName}, {r.ScopeLevel.ToLowerInvariant()})"))}{(g.Count() > 5 ? ", …" : "")}.",
                "Subscription", SubRef(g.Key), "", g.Key);

        var wildcard = iam.CustomRoles.Where(r => r.HasWildcardActions).ToList();
        b.Check(lp, 10, iam.CustomRoles.Count - wildcard.Count, iam.CustomRoles.Count,
            iam.CustomRoles.Count == 0 ? "No custom roles." : wildcard.Count == 0 ? $"None of the {iam.CustomRoles.Count} custom role(s) use wildcard actions." : $"{wildcard.Count} of {iam.CustomRoles.Count} custom role(s) use wildcard actions.",
            $"Replace wildcard actions in {wildcard.Count} custom role(s) with explicit operations.", "wildcard");
        if (wildcard.Count > 0) b.Cap("wildcard", "B", "A custom role grants wildcard actions.");
        foreach (var r in wildcard)
            findings.Add(area, "Medium", "Custom role with wildcard", $"Custom role '{r.Name}' grants {string.Join(", ", r.Actions.Where(a => a.Contains('*')).Take(3))}.", r.Name, r.Id, "", r.SubscriptionId);

        // ── 2. Group-based access (15) ───────────────────────────────────────
        var grp = b.Category(GroupsCategory, 15);
        var userOrGroup = ras.Where(r => r.IsUser || r.IsGroup).ToList();
        var viaGroup = userOrGroup.Count(r => r.IsGroup);
        b.Check(grp, 15, viaGroup, userOrGroup.Count,
            userOrGroup.Count == 0 ? "No user or group assignments." : $"{viaGroup} of {userOrGroup.Count} people-facing assignment(s) are to groups ({(userOrGroup.Count == 0 ? 0 : viaGroup * 100 / userOrGroup.Count)}%).",
            $"Convert the {userOrGroup.Count - viaGroup} direct user assignment(s) to group assignments.");

        // ── 3. Workload identities (25) ──────────────────────────────────────
        var wl = b.Category(WorkloadCategory, 25);
        var spOwners = ras.Where(r => r.IsServicePrincipal && r.IsOwner).ToList();
        var sps = ras.Where(r => r.IsServicePrincipal).ToList();
        b.Check(wl, 8, sps.Count - spOwners.Count, sps.Count,
            sps.Count == 0 ? "No service principal assignments." : spOwners.Count == 0 ? $"None of the {sps.Count} service principal assignment(s) is Owner." : $"{spOwners.Count} service principal assignment(s) are Owner.",
            $"Downgrade the {spOwners.Count} service principal Owner assignment(s) to a narrower role.");
        foreach (var r in spOwners)
            findings.Add(area, "Medium", "Service principal with Owner", $"Service principal '{r.Display}' is Owner at {r.ScopeLevel.ToLowerInvariant()} scope.", r.Display, r.Id, "", r.SubscriptionId);

        var compute = scan.VirtualMachines.Count + scan.WebApps.Count;
        var withMi = scan.VirtualMachines.Count(v => v.HasManagedIdentity) + scan.WebApps.Count(a => a.HasManagedIdentity);
        b.Check(wl, 10, withMi, compute,
            compute == 0 ? "No compute resources to assess." : $"{withMi} of {compute} VM(s) and App Service(s) have a managed identity.",
            $"Assign managed identities to the {compute - withMi} compute resource(s) without one.");

        if (iam.AppsWithExpiredCredentials is null && iam.AppsWithLongLivedCredentials is null)
        {
            wl.Earned += 4;
            wl.Details.Add("App registration credentials could not be read — half points awarded.");
        }
        else
        {
            var expired = iam.AppsWithExpiredCredentials ?? 0;
            var longLived = iam.AppsWithLongLivedCredentials ?? 0;
            if (expired == 0 && longLived == 0)
            {
                wl.Earned += 7;
                wl.Details.Add("No app registration has expired or long-lived credentials.");
            }
            else
            {
                wl.Earned += expired == 0 ? 3 : longLived == 0 ? 4 : 0;
                wl.Details.Add($"{expired} app registration(s) with expired credentials, {longLived} with credentials valid for more than two years.");
                b.Improve("Clean up expired app credentials and rotate long-lived secrets.", 7 - (expired == 0 ? 3 : longLived == 0 ? 4 : 0));
                if (expired > 0) findings.Add(area, "Low", "Expired app credentials", $"{expired} app registration(s) still carry expired client secrets or certificates.", "Tenant", $"/tenants/{scan.TenantId}");
                if (longLived > 0) findings.Add(area, "Low", "Long-lived app credentials", $"{longLived} app registration(s) have client secrets valid for more than two years.", "Tenant", $"/tenants/{scan.TenantId}");
            }
        }

        // ── 4. Assignment hygiene (15) ───────────────────────────────────────
        var hyg = b.Category(HygieneCategory, 15);
        if (!iam.PrincipalsResolved)
        {
            hyg.Earned = 8;
            hyg.Details.Add("Principals could not be resolved against the directory — half points awarded.");
        }
        else
        {
            var orphaned = ras.Where(r => r.IsOrphaned == true).ToList();
            b.Check(hyg, 8, ras.Count - orphaned.Count, ras.Count,
                orphaned.Count == 0 ? "No role assignment points at a deleted principal." : $"{orphaned.Count} of {ras.Count} role assignment(s) point at principals that no longer exist.",
                $"Delete the {orphaned.Count} orphaned role assignment(s).");
            foreach (var r in orphaned)
                findings.Add(area, "Low", "Orphaned role assignment", $"Role assignment of {r.RoleName} at {r.ScopeLevel.ToLowerInvariant()} scope targets principal {r.PrincipalId}, which was not found in this directory (deleted, or from another tenant).", r.PrincipalId, r.Id, "", r.SubscriptionId);

            var guests = ras.Where(r => r.IsGuest == true).ToList();
            b.Check(hyg, 7, ras.Count - guests.Count, ras.Count,
                guests.Count == 0 ? "No guest accounts hold role assignments." : $"{guests.Count} role assignment(s) are held by guest accounts.",
                $"Review the {guests.Count} role assignment(s) held by guest accounts.");
            foreach (var r in guests)
                findings.Add(area, guests.Any(g => g.IsPrivileged) ? "Medium" : "Low", "Guest with role assignment", $"Guest '{r.Display}' holds {r.RoleName} at {r.ScopeLevel.ToLowerInvariant()} scope.", r.Display, r.Id, "", r.SubscriptionId);
        }

        // ── 5. Scope discipline (15) ─────────────────────────────────────────
        var sc = b.Category(ScopeCategory, 15);
        var uaaUsers = ras.Where(r => r.IsUserAccessAdmin && r.IsUser).ToList();
        if (uaaUsers.Count == 0)
        {
            sc.Earned += 7;
            sc.Details.Add("No individual user holds User Access Administrator.");
        }
        else
        {
            sc.Details.Add($"{uaaUsers.Count} user(s) hold User Access Administrator directly.");
            b.Improve($"Remove User Access Administrator from {uaaUsers.Count} individual user(s).", 7);
            foreach (var r in uaaUsers)
                findings.Add(area, "Medium", "User Access Administrator on user", $"User '{r.Display}' holds User Access Administrator at {r.ScopeLevel.ToLowerInvariant()} scope.", r.Display, r.Id, "", r.SubscriptionId);
        }

        var nonPrivileged = ras.Where(r => !r.IsPrivileged).ToList();
        var scopedNarrow = nonPrivileged.Count(r => !r.IsSubscriptionOrAbove);
        var narrowPts = nonPrivileged.Count == 0 ? 8 : (int)Math.Round(8 * Math.Clamp(scopedNarrow / (double)Math.Max(1, nonPrivileged.Count) / 0.5, 0, 1));
        sc.Earned += narrowPts;
        sc.Details.Add(nonPrivileged.Count == 0 ? "No non-privileged assignments." : $"{scopedNarrow} of {nonPrivileged.Count} non-privileged assignment(s) are scoped to a resource group or resource.");
        if (narrowPts < 8) b.Improve("Scope non-privileged roles to resource groups instead of the whole subscription.", 8 - narrowPts);

        var parts = new List<string> { $"{ras.Count} role assignment{(ras.Count == 1 ? "" : "s")}" };
        if (iam.CustomRoles.Count > 0) parts.Add($"{iam.CustomRoles.Count} custom role{(iam.CustomRoles.Count == 1 ? "" : "s")}");
        if (iam.UserAssignedIdentities.Count > 0) parts.Add($"{iam.UserAssignedIdentities.Count} user-assigned identit{(iam.UserAssignedIdentities.Count == 1 ? "y" : "ies")}");
        return b.Build(ras.Count + iam.CustomRoles.Count, string.Join(", ", parts));
    }
}
