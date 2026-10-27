using System.Text.Json;

namespace RateMyAzureSubscriptions.Services.Azure;

/// <summary>
/// Thin, read-only access to the Azure data planes the audit needs: Azure Resource Graph, ARM and
/// Microsoft Graph. Everything the app knows about an environment comes through here, so tests can
/// substitute canned JSON.
/// </summary>
public interface IAzureApi
{
    /// <summary>Runs an Azure Resource Graph query across the given subscriptions, following $skipToken paging.</summary>
    Task<List<JsonElement>> QueryResourceGraphAsync(string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default);

    /// <summary>GETs an ARM collection URL and returns the concatenated "value" items across nextLink pages.</summary>
    Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default);

    /// <summary>GETs a single ARM resource; returns null on 404.</summary>
    Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default);

    /// <summary>GETs a Microsoft Graph URL (v1.0 or beta, relative to the Graph root) following @odata.nextLink; returns the "value" items, or the object itself wrapped in a list.</summary>
    Task<List<JsonElement>> GetGraphListAsync(string relativeUrl, string? tenantId, CancellationToken ct = default, bool consistencyLevelEventual = false);

    /// <summary>GETs a single Microsoft Graph object (relative to the Graph root); returns null on 404.</summary>
    Task<JsonElement?> GetGraphAsync(string relativeUrl, string? tenantId, CancellationToken ct = default);

    /// <summary>POSTs a JSON body to Microsoft Graph and returns the "value" items of the response.</summary>
    Task<List<JsonElement>> PostGraphAsync(string relativeUrl, string jsonBody, string? tenantId, CancellationToken ct = default);
}
