using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// Orchestrates the audit steps against either Azure or the built-in sample estate, so the UI never
/// has to know which one it is talking to. Areas can be audited all at once or one at a time; a later
/// per-area scan merges into the existing result instead of replacing it.
/// </summary>
public sealed class AuditFlowService
{
    private readonly SessionState _state;
    private readonly AuditDiscoveryService _discovery;

    public AuditFlowService(SessionState state, AuditDiscoveryService discovery)
    {
        _state = state;
        _discovery = discovery;
    }

    public SessionState State => _state;

    public IReadOnlyList<SubscriptionInfo> Subscriptions =>
        _state.DemoMode ? DemoDataService.Subscriptions() : _state.Subscriptions;

    public string TenantName(string tenantId) =>
        _state.DemoMode ? DemoDataService.Tenants()[DemoDataService.TenantId].BestName : _state.TenantName(tenantId);

    public string SubscriptionName(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.DisplayName ?? subscriptionId;

    public Task LoadSubscriptionsAsync(bool force = false, CancellationToken ct = default) =>
        _state.DemoMode ? Task.CompletedTask : _state.EnsureLoadedAsync(force, ct);

    public void EnterDemoMode()
    {
        _state.DemoMode = true;
        _state.Reset();
        _state.SelectedTenantId = DemoDataService.TenantId;
    }

    public void ExitDemoMode()
    {
        _state.DemoMode = false;
        _state.Reset();
    }

    public Task<Dictionary<string, SubscriptionSummary>> GetSummariesAsync(
        IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default) =>
        _state.DemoMode
            ? Task.FromResult(DemoDataService.Summaries())
            : _discovery.GetSummariesAsync(subscriptionIds, tenantId, ct);

    private string? SelectedTenantId =>
        Subscriptions.Where(s => _state.SelectedSubscriptionIds.Contains(s.SubscriptionId))
            .Select(s => s.TenantId).FirstOrDefault(t => !string.IsNullOrEmpty(t)) ?? _state.SelectedTenantId;

    /// <summary>
    /// Scans the selected subscriptions for the given areas (default: the areas chosen on the scope step).
    /// When a scan of the same subscriptions already exists, the new areas are merged into it.
    /// </summary>
    public async Task<AuditScanResult> ScanAsync(IReadOnlyCollection<AuditArea>? areas = null, IProgress<string>? progress = null, CancellationToken ct = default)
    {
        var ids = _state.SelectedSubscriptionIds.ToList();
        var wanted = new HashSet<AuditArea>(areas ?? _state.SelectedAreas);
        if (wanted.Count == 0) wanted = new HashSet<AuditArea>(AuditAreaExtensions.All);
        AuditScanResult fresh;

        if (_state.DemoMode)
        {
            progress?.Report("Loading sample estate…");
            await Task.Delay(700, ct);
            fresh = DemoDataService.Scan(ids, wanted);
        }
        else
        {
            fresh = await _discovery.ScanAsync(ids, SelectedTenantId, wanted, progress, ct);
        }

        var existing = _state.Scan;
        if (existing is not null && existing.SubscriptionIds.ToHashSet(StringComparer.OrdinalIgnoreCase).SetEquals(fresh.SubscriptionIds))
        {
            Merge(existing, fresh, wanted);
            AuditDiscoveryService.Finalize(existing);
            _state.ScanError = null;
            return existing;
        }

        _state.Scan = fresh;
        _state.ScanError = null;
        return fresh;
    }

    /// <summary>Audits one more area and merges it into the current scan.</summary>
    public Task<AuditScanResult> ScanAreaAsync(AuditArea area, IProgress<string>? progress = null, CancellationToken ct = default) =>
        ScanAsync([area], progress, ct);

    /// <summary>
    /// Copies the freshly collected data for <paramref name="areas"/> into <paramref name="target"/>, keeping the
    /// previously collected data for every other area so earlier grades are not disturbed.
    /// </summary>
    internal static void Merge(AuditScanResult target, AuditScanResult fresh, IReadOnlySet<AuditArea> areas)
    {
        target.Warnings = target.Warnings.Where(w => !w.StartsWith("Sample data", StringComparison.Ordinal)).Concat(fresh.Warnings).Distinct().ToList();
        target.Issues = target.Issues.Where(i => !areas.Contains(i.Area)).Concat(fresh.Issues.Where(i => areas.Contains(i.Area))).ToList();
        if (areas.Contains(AuditArea.Compute))
        {
            target.VirtualMachines = fresh.VirtualMachines;
            target.Disks = fresh.Disks;
            target.WebApps = fresh.WebApps;
            target.AppServicePlans = fresh.AppServicePlans;
        }
        else if (target.VirtualMachines.Count == 0 && target.WebApps.Count == 0)
        {
            // Cross-area facts (public IPs on VMs, managed identities) come from the cheap inventory query; keep them.
            target.VirtualMachines = fresh.VirtualMachines;
            target.WebApps = fresh.WebApps;
            target.AppServicePlans = fresh.AppServicePlans;
            target.Disks = fresh.Disks;
        }
        if (areas.Contains(AuditArea.Networking))
        {
            target.VirtualNetworks = fresh.VirtualNetworks;
            target.NetworkSecurityGroups = fresh.NetworkSecurityGroups;
            target.PublicIps = fresh.PublicIps;
            target.NetworkInterfaces = fresh.NetworkInterfaces;
            target.PrivateEndpoints = fresh.PrivateEndpoints;
            target.NetworkWatchers = fresh.NetworkWatchers;
            target.FlowLogs = fresh.FlowLogs;
            target.PrivateDnsZones = fresh.PrivateDnsZones;
            target.BastionCount = fresh.BastionCount;
            target.FirewallCount = fresh.FirewallCount;
        }
        else if (target.VirtualNetworks.Count == 0 && target.NetworkInterfaces.Count == 0)
        {
            target.NetworkInterfaces = fresh.NetworkInterfaces;
            target.PrivateEndpoints = fresh.PrivateEndpoints;
        }
        if (areas.Contains(AuditArea.Storage) || target.StorageAccounts.Count == 0) target.StorageAccounts = fresh.StorageAccounts;
        if (areas.Contains(AuditArea.Security))
        {
            target.KeyVaults = fresh.KeyVaults;
            target.SqlServers = fresh.SqlServers;
            target.SubscriptionSecurity = fresh.SubscriptionSecurity;
        }
        else if (target.KeyVaults.Count == 0 && target.SqlServers.Count == 0)
        {
            target.KeyVaults = fresh.KeyVaults;
            target.SqlServers = fresh.SqlServers;
        }
        if (areas.Contains(AuditArea.Iam)) target.Iam = fresh.Iam;
        if (areas.Contains(AuditArea.EntraId)) target.Entra = fresh.Entra;
        target.AssessedAreas.UnionWith(areas);
        target.ExclusionPatterns = fresh.ExclusionPatterns;
        target.ExcludedCount = fresh.ExcludedCount;
    }

    public AuditReportContext ReportContext()
    {
        var subs = Subscriptions.Where(s => _state.SelectedSubscriptionIds.Contains(s.SubscriptionId))
            .OrderBy(s => s.DisplayName, StringComparer.OrdinalIgnoreCase).ToList();
        var tenantId = subs.Select(s => s.TenantId).FirstOrDefault(t => !string.IsNullOrEmpty(t)) ?? _state.SelectedTenantId ?? "";
        var tenantName = string.IsNullOrEmpty(tenantId) ? "" : TenantName(tenantId);
        if (!string.IsNullOrEmpty(_state.Scan?.Entra.DisplayName)) tenantName = _state.Scan.Entra.DisplayName;
        return new AuditReportContext
        {
            CustomerName = tenantName,
            TenantName = tenantName,
            ReportAuthor = Environment.UserName,
            ScanDate = _state.Scan?.CompletedAt ?? DateTime.Now,
            SubscriptionLines = subs.Select(s => $"{s.DisplayName} ({s.SubscriptionId})").ToList(),
            SubscriptionNames = subs.ToDictionary(s => s.SubscriptionId, s => s.DisplayName, StringComparer.OrdinalIgnoreCase),
            Scan = _state.Scan,
            VisibleSeverities = new HashSet<string>(_state.VisibleSeverities, StringComparer.OrdinalIgnoreCase),
        };
    }
}
