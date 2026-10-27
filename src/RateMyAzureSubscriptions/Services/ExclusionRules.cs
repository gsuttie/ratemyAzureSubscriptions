using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// Resources that must never take part in a review: by default anything whose name or resource group
/// contains "restore" (restore tests). Configurable with Audit:ExcludePatterns in appsettings.json.
/// </summary>
public sealed class ExclusionRules
{
    public static readonly ExclusionRules Default = new(["restore"]);

    public IReadOnlyList<string> Patterns { get; }

    public ExclusionRules(IEnumerable<string> patterns) =>
        Patterns = patterns.Where(p => !string.IsNullOrWhiteSpace(p)).Select(p => p.Trim()).Distinct(StringComparer.OrdinalIgnoreCase).ToList();

    public static ExclusionRules FromConfiguration(IConfiguration? configuration)
    {
        var configured = configuration?.GetSection("Audit:ExcludePatterns").Get<string[]>();
        return configured is { Length: > 0 } ? new ExclusionRules(configured) : Default;
    }

    public bool Matches(string? text) =>
        !string.IsNullOrEmpty(text) && Patterns.Any(p => text.Contains(p, StringComparison.OrdinalIgnoreCase));

    public bool IsExcluded(string name, string resourceGroup) => Matches(name) || Matches(resourceGroup);
    public bool IsExcluded(ResourceBase r) => IsExcluded(r.Name, r.ResourceGroup);

    /// <summary>True when any resource-group or resource-name segment of an ARM ID matches.</summary>
    public bool IsExcludedId(string? id)
    {
        if (string.IsNullOrEmpty(id)) return false;
        var segs = id.Split('/', StringSplitOptions.RemoveEmptyEntries);
        for (var i = 1; i < segs.Length; i++)
            if (segs[i - 1].Equals("resourceGroups", StringComparison.OrdinalIgnoreCase) && Matches(segs[i])) return true;

        // After ".../providers/<namespace>", segments alternate <type>/<name>; check every name (sub-resources included).
        var providers = Array.FindIndex(segs, s => s.Equals("providers", StringComparison.OrdinalIgnoreCase));
        if (providers >= 0)
            for (var i = providers + 3; i < segs.Length; i += 2)
                if (Matches(segs[i])) return true;
        return false;
    }

    /// <summary>KQL predicate for Resource Graph so excluded resources never leave Azure.</summary>
    public string KqlFilter()
    {
        if (Patterns.Count == 0) return "";
        var parts = Patterns.Select(p => $"name !contains '{p.Replace("'", "\\'")}' and resourceGroup !contains '{p.Replace("'", "\\'")}'");
        return "| where " + string.Join(" and ", parts) + " ";
    }

    public string Description => Patterns.Count == 0 ? "" : string.Join(", ", Patterns.Select(p => $"'{p}'"));

    /// <summary>Drops excluded resources from every inventory list; returns how many were removed.</summary>
    public int Apply(AuditScanResult r)
    {
        var removed = 0;
        int Filter<T>(List<T> list) where T : ResourceBase
        {
            var before = list.Count;
            list.RemoveAll(IsExcluded);
            return before - list.Count;
        }
        removed += Filter(r.VirtualMachines);
        removed += Filter(r.Disks);
        removed += Filter(r.WebApps);
        removed += Filter(r.AppServicePlans);
        removed += Filter(r.VirtualNetworks);
        foreach (var v in r.VirtualNetworks)
            removed += v.Subnets.RemoveAll(s => Matches(s.Name));
        removed += Filter(r.NetworkSecurityGroups);
        removed += Filter(r.PublicIps);
        removed += Filter(r.NetworkInterfaces);
        removed += Filter(r.PrivateEndpoints);
        removed += Filter(r.NetworkWatchers);
        removed += Filter(r.FlowLogs);
        removed += Filter(r.PrivateDnsZones);
        removed += Filter(r.StorageAccounts);
        removed += Filter(r.KeyVaults);
        removed += Filter(r.SqlServers);
        removed += Filter(r.Iam.UserAssignedIdentities);
        var ra = r.Iam.RoleAssignments.Count;
        r.Iam.RoleAssignments.RemoveAll(a => IsExcludedId(a.Scope) || Matches(a.PrincipalName));
        removed += ra - r.Iam.RoleAssignments.Count;
        var cr = r.Iam.CustomRoles.Count;
        r.Iam.CustomRoles.RemoveAll(c => Matches(c.Name));
        removed += cr - r.Iam.CustomRoles.Count;
        r.ExcludedCount += removed;
        return removed;
    }
}
