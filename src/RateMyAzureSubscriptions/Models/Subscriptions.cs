namespace RateMyAzureSubscriptions.Models;

public sealed class SubscriptionInfo
{
    public string SubscriptionId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string State { get; set; } = string.Empty;
    public string TenantId { get; set; } = string.Empty;
}

public sealed class TenantInfo
{
    public string TenantId { get; set; } = string.Empty;
    public string DisplayName { get; set; } = string.Empty;
    public string DefaultDomain { get; set; } = string.Empty;

    public string BestName => string.IsNullOrWhiteSpace(DisplayName) ? TenantId : DisplayName;
}

/// <summary>Resource counts for one subscription (from Azure Resource Graph), shown on the scope step.</summary>
public sealed class SubscriptionSummary
{
    public string SubscriptionId { get; set; } = string.Empty;
    public int ResourceCount { get; set; }
    public int ResourceGroupCount { get; set; }
}
