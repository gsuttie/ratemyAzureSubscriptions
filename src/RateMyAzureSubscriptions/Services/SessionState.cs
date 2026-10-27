using RateMyAzureSubscriptions.Models;

namespace RateMyAzureSubscriptions.Services;

/// <summary>
/// Per-circuit (scoped) state: subscriptions loaded once, the selected scope, and the scan result the
/// user moves between steps with.
/// </summary>
public sealed class SessionState
{
    private readonly AzureSubscriptionService _subscriptions;
    private readonly SemaphoreSlim _loadLock = new(1, 1);
    private bool _loaded;

    public SessionState(AzureSubscriptionService subscriptions) => _subscriptions = subscriptions;

    public List<SubscriptionInfo> Subscriptions { get; private set; } = new();
    public Dictionary<string, TenantInfo> Tenants { get; private set; } = new(StringComparer.OrdinalIgnoreCase);
    public string? LoadError { get; private set; }
    public bool IsLoaded => _loaded;

    /// <summary>True when the app runs on built-in sample data instead of Azure.</summary>
    public bool DemoMode { get; set; }

    public HashSet<string> SelectedSubscriptionIds { get; } = new(StringComparer.OrdinalIgnoreCase);
    public string? SelectedTenantId { get; set; }

    /// <summary>Areas to audit on the next scan; areas left out can be audited on demand from the Grades step.</summary>
    public HashSet<AuditArea> SelectedAreas { get; } = new(AuditAreaExtensions.All);

    /// <summary>Severities shown in the findings lists (Grades and Improvement plan). Reports always include everything.</summary>
    public HashSet<string> VisibleSeverities { get; } = new(StringComparer.OrdinalIgnoreCase) { "High", "Medium", "Low" };
    public bool IsVisible(AuditFinding f) => VisibleSeverities.Contains(f.Severity);
    public void ToggleSeverity(string severity) { if (!VisibleSeverities.Remove(severity)) VisibleSeverities.Add(severity); }
    public AuditScanResult? Scan { get; set; }
    public string? ScanError { get; set; }
    public bool HasScan => Scan is not null;

    public async Task EnsureLoadedAsync(bool force = false, CancellationToken ct = default)
    {
        if (_loaded && !force) return;
        await _loadLock.WaitAsync(ct);
        try
        {
            if (_loaded && !force) return;
            LoadError = null;
            if (force) _subscriptions.Reset();
            try
            {
                Subscriptions = await _subscriptions.GetSubscriptionsAsync(ct);
                Tenants = await _subscriptions.GetTenantsAsync(ct);
                if (Subscriptions.Count == 0)
                    LoadError = "No subscriptions are visible to the current credential. Run 'az login' and make sure the account has Reader access.";
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                Subscriptions = new();
                LoadError = "Could not list subscriptions. Run 'az login' (optionally with --tenant <id>) in a terminal, then retry. Details: " + ex.Message;
            }
            _loaded = true;
        }
        finally
        {
            _loadLock.Release();
        }
    }

    public string TenantName(string tenantId) =>
        Tenants.TryGetValue(tenantId, out var t) ? t.BestName : tenantId;

    public string SubscriptionName(string subscriptionId) =>
        Subscriptions.FirstOrDefault(s => s.SubscriptionId.Equals(subscriptionId, StringComparison.OrdinalIgnoreCase))?.DisplayName
        ?? subscriptionId;

    public void Reset()
    {
        Scan = null;
        ScanError = null;
        SelectedSubscriptionIds.Clear();
        SelectedTenantId = null;
    }
}
