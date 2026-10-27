using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Azure.Core;

namespace RateMyAzureSubscriptions.Services.Azure;

/// <summary>Live implementation over HTTPS using the configured TokenCredential (az login by default).</summary>
public sealed class AzureApi : IAzureApi
{
    public const string ArmBase = "https://management.azure.com";
    public const string GraphBase = "https://graph.microsoft.com";
    private static readonly string[] ArmScopes = ["https://management.azure.com/.default"];
    private static readonly string[] GraphScopes = ["https://graph.microsoft.com/.default"];

    private readonly TokenCredential _credential;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly ILogger<AzureApi> _logger;
    private readonly Dictionary<string, AccessToken> _tokenCache = new(StringComparer.OrdinalIgnoreCase);
    private readonly SemaphoreSlim _tokenLock = new(1, 1);

    public AzureApi(TokenCredential credential, IHttpClientFactory httpClientFactory, ILogger<AzureApi> logger)
    {
        _credential = credential;
        _httpClientFactory = httpClientFactory;
        _logger = logger;
    }

    // Azure Resource Graph allows a small per-user quota (about 15 queries per 5-second window, signalled by
    // x-ms-user-quota-remaining / x-ms-user-quota-resets-after). All ARG calls go through one gate so they
    // run one at a time, wait when the quota is exhausted, and back off on 429 instead of failing the scan.
    private readonly SemaphoreSlim _argGate = new(1, 1);
    private int _argQuotaRemaining = int.MaxValue;
    private DateTimeOffset _argQuotaResetAt = DateTimeOffset.MinValue;
    private const int MaxArgAttempts = 5;

    public async Task<List<JsonElement>> QueryResourceGraphAsync(
        string query, IReadOnlyCollection<string> subscriptionIds, string? tenantId, CancellationToken ct = default)
    {
        var rows = new List<JsonElement>();
        var client = _httpClientFactory.CreateClient();
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);
        string? skipToken = null;

        do
        {
            var options = new Dictionary<string, object?> { ["resultFormat"] = "objectArray" };
            if (skipToken is not null) options["$skipToken"] = skipToken;

            var body = JsonSerializer.Serialize(new Dictionary<string, object?>
            {
                ["subscriptions"] = subscriptionIds,
                ["query"] = query,
                ["options"] = options
            });

            var json = await SendArgAsync(client, token, body, ct);

            using var doc = JsonDocument.Parse(json);
            if (doc.RootElement.TryGetProperty("data", out var data) && data.ValueKind == JsonValueKind.Array)
                foreach (var row in data.EnumerateArray())
                    rows.Add(row.Clone());

            skipToken = doc.RootElement.TryGetProperty("$skipToken", out var st) ? st.GetString() : null;
        } while (!string.IsNullOrEmpty(skipToken));

        return rows;
    }

    private async Task<string> SendArgAsync(HttpClient client, string token, string body, CancellationToken ct)
    {
        await _argGate.WaitAsync(ct);
        try
        {
            for (var attempt = 1; ; attempt++)
            {
                if (_argQuotaRemaining <= 0 && _argQuotaResetAt > DateTimeOffset.UtcNow)
                {
                    var wait = _argQuotaResetAt - DateTimeOffset.UtcNow + TimeSpan.FromMilliseconds(250);
                    _logger.LogInformation("Resource Graph quota exhausted; waiting {Wait:0.0}s.", wait.TotalSeconds);
                    await Task.Delay(wait, ct);
                }

                using var request = new HttpRequestMessage(HttpMethod.Post,
                    $"{ArmBase}/providers/Microsoft.ResourceGraph/resources?api-version=2022-10-01");
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
                request.Content = new StringContent(body, Encoding.UTF8, "application/json");

                using var response = await client.SendAsync(request, ct);
                var json = await response.Content.ReadAsStringAsync(ct);
                ReadArgQuota(response);

                if (response.IsSuccessStatusCode) return json;

                if (response.StatusCode == HttpStatusCode.TooManyRequests && attempt < MaxArgAttempts)
                {
                    var delay = response.Headers.RetryAfter?.Delta
                        ?? (_argQuotaResetAt > DateTimeOffset.UtcNow ? _argQuotaResetAt - DateTimeOffset.UtcNow : TimeSpan.FromSeconds(5));
                    delay += TimeSpan.FromMilliseconds(500 * attempt);
                    _logger.LogWarning("Resource Graph throttled (attempt {Attempt}); retrying in {Delay:0.0}s.", attempt, delay.TotalSeconds);
                    await Task.Delay(delay, ct);
                    continue;
                }

                throw new InvalidOperationException(
                    $"Azure Resource Graph query failed ({(int)response.StatusCode}): {Truncate(json, 400)}");
            }
        }
        finally
        {
            _argGate.Release();
        }
    }

    private void ReadArgQuota(HttpResponseMessage response)
    {
        if (response.Headers.TryGetValues("x-ms-user-quota-remaining", out var rem) && int.TryParse(rem.FirstOrDefault(), out var remaining))
            _argQuotaRemaining = remaining;
        if (response.Headers.TryGetValues("x-ms-user-quota-resets-after", out var reset) && TimeSpan.TryParse(reset.FirstOrDefault(), out var after))
            _argQuotaResetAt = DateTimeOffset.UtcNow + after;
    }

    public async Task<List<JsonElement>> GetArmListAsync(string url, string? tenantId, CancellationToken ct = default)
    {
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);
        return await GetListAsync(url, token, "nextLink", ct, eventual: false);
    }

    public async Task<JsonElement?> GetArmAsync(string url, string? tenantId, CancellationToken ct = default)
    {
        var token = await GetTokenAsync(tenantId, ArmScopes, ct);
        return await GetOneAsync(url, token, ct);
    }

    public async Task<List<JsonElement>> GetGraphListAsync(string relativeUrl, string? tenantId, CancellationToken ct = default, bool consistencyLevelEventual = false)
    {
        var token = await GetTokenAsync(tenantId, GraphScopes, ct);
        return await GetListAsync(GraphUrl(relativeUrl), token, "@odata.nextLink", ct, consistencyLevelEventual);
    }

    public async Task<JsonElement?> GetGraphAsync(string relativeUrl, string? tenantId, CancellationToken ct = default)
    {
        var token = await GetTokenAsync(tenantId, GraphScopes, ct);
        return await GetOneAsync(GraphUrl(relativeUrl), token, ct);
    }

    public async Task<List<JsonElement>> PostGraphAsync(string relativeUrl, string jsonBody, string? tenantId, CancellationToken ct = default)
    {
        var client = _httpClientFactory.CreateClient();
        var token = await GetTokenAsync(tenantId, GraphScopes, ct);
        using var request = new HttpRequestMessage(HttpMethod.Post, GraphUrl(relativeUrl));
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        request.Content = new StringContent(jsonBody, Encoding.UTF8, "application/json");
        using var response = await client.SendAsync(request, ct);
        var json = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {Truncate(json, 300)}");
        return ExtractValue(json);
    }

    private static string GraphUrl(string relative) =>
        relative.StartsWith("http", StringComparison.OrdinalIgnoreCase) ? relative : $"{GraphBase}/{relative.TrimStart('/')}";

    private async Task<List<JsonElement>> GetListAsync(string url, string token, string nextLinkProperty, CancellationToken ct, bool eventual)
    {
        var items = new List<JsonElement>();
        var client = _httpClientFactory.CreateClient();
        var next = url;

        while (!string.IsNullOrEmpty(next))
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, next);
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
            if (eventual) request.Headers.Add("ConsistencyLevel", "eventual");

            using var response = await client.SendAsync(request, ct);
            var json = await response.Content.ReadAsStringAsync(ct);
            if (!response.IsSuccessStatusCode)
                throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {Truncate(json, 300)}");

            using var doc = JsonDocument.Parse(json);
            var root = doc.RootElement;
            if (root.ValueKind != JsonValueKind.Object)
            {
                // Scalar responses such as Graph's /$count endpoints.
                items.Add(root.Clone());
                break;
            }
            if (root.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
                foreach (var item in value.EnumerateArray())
                    items.Add(item.Clone());
            else
                items.Add(root.Clone());

            next = root.TryGetProperty(nextLinkProperty, out var nl) ? nl.GetString() : null;
        }
        return items;
    }

    private async Task<JsonElement?> GetOneAsync(string url, string token, CancellationToken ct)
    {
        var client = _httpClientFactory.CreateClient();
        using var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);
        using var response = await client.SendAsync(request, ct);
        if (response.StatusCode == HttpStatusCode.NotFound) return null;
        var json = await response.Content.ReadAsStringAsync(ct);
        if (!response.IsSuccessStatusCode)
            throw new InvalidOperationException($"HTTP {(int)response.StatusCode}: {Truncate(json, 300)}");
        using var doc = JsonDocument.Parse(json);
        return doc.RootElement.Clone();
    }

    private static List<JsonElement> ExtractValue(string json)
    {
        var items = new List<JsonElement>();
        using var doc = JsonDocument.Parse(json);
        if (doc.RootElement.TryGetProperty("value", out var value) && value.ValueKind == JsonValueKind.Array)
            foreach (var item in value.EnumerateArray())
                items.Add(item.Clone());
        return items;
    }

    private async Task<string> GetTokenAsync(string? tenantId, string[] scopes, CancellationToken ct)
    {
        var key = $"{tenantId}|{scopes[0]}";
        await _tokenLock.WaitAsync(ct);
        try
        {
            if (_tokenCache.TryGetValue(key, out var cached) && cached.ExpiresOn > DateTimeOffset.UtcNow.AddMinutes(5))
                return cached.Token;

            var context = new TokenRequestContext(scopes, tenantId: string.IsNullOrEmpty(tenantId) ? null : tenantId);
            var token = await _credential.GetTokenAsync(context, ct);
            _tokenCache[key] = token;
            return token.Token;
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogWarning(ex, "Token acquisition failed for tenant {TenantId} / {Scope}.", tenantId, scopes[0]);
            throw new InvalidOperationException(
                $"Could not acquire a token for {scopes[0]}. Run 'az login' (optionally with --tenant) and try again. " + ex.Message, ex);
        }
        finally
        {
            _tokenLock.Release();
        }
    }

    private static string Truncate(string s, int max) => s.Length <= max ? s : s[..max] + "…";
}
