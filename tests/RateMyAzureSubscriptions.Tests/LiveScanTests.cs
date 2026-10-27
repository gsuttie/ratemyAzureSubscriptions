using Azure.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using RateMyAzureSubscriptions.Models;
using RateMyAzureSubscriptions.Services;
using RateMyAzureSubscriptions.Services.Azure;
using Xunit;
using Xunit.Abstractions;

namespace RateMyAzureSubscriptions.Tests;

/// <summary>
/// Optional end-to-end smoke test against the real Azure the CLI is signed in to. Read-only.
/// Runs only when RMAS_LIVE=1 (and optionally RMAS_SUBSCRIPTION=&lt;id&gt;); otherwise it is a no-op so CI stays offline.
/// </summary>
public class LiveScanTests
{
    private readonly ITestOutputHelper _out;
    public LiveScanTests(ITestOutputHelper output) => _out = output;

    [Fact]
    public async Task LiveScan_CurrentSubscription()
    {
        if (Environment.GetEnvironmentVariable("RMAS_LIVE") != "1")
        {
            _out.WriteLine("RMAS_LIVE is not set; skipping the live scan.");
            return;
        }

        var services = new ServiceCollection();
        services.AddHttpClient();
        var provider = services.BuildServiceProvider();
        var credential = new AzureCliCredential();
        var api = new AzureApi(credential, provider.GetRequiredService<IHttpClientFactory>(), NullLogger<AzureApi>.Instance);
        var subs = new AzureSubscriptionService(credential, NullLogger<AzureSubscriptionService>.Instance);

        var all = await subs.GetSubscriptionsAsync();
        Assert.NotEmpty(all);
        var wanted = Environment.GetEnvironmentVariable("RMAS_SUBSCRIPTION");
        var target = all.FirstOrDefault(s => s.SubscriptionId.Equals(wanted, StringComparison.OrdinalIgnoreCase)) ?? all[0];
        _out.WriteLine($"Scanning {target.DisplayName} ({target.SubscriptionId}) in tenant {target.TenantId}");

        var discovery = new AuditDiscoveryService(api, NullLogger<AuditDiscoveryService>.Instance);
        var progress = new Progress<string>(m => _out.WriteLine("  " + m));
        var scan = await discovery.ScanAsync([target.SubscriptionId], target.TenantId, progress);

        _out.WriteLine($"Resources: {scan.TotalResources}  VMs {scan.VirtualMachines.Count}  Apps {scan.WebApps.Count}  Plans {scan.AppServicePlans.Count}  VNets {scan.VirtualNetworks.Count}  NSGs {scan.NetworkSecurityGroups.Count}  PIPs {scan.PublicIps.Count}  Storage {scan.StorageAccounts.Count}  KV {scan.KeyVaults.Count}  SQL {scan.SqlServers.Count}  RAs {scan.Iam.RoleAssignments.Count}  CA {scan.Entra.ConditionalAccessPolicies.Count}");
        _out.WriteLine($"Overall: {AuditRatingService.OverallGrade(scan)} ({scan.OverallScore}/100)");
        foreach (var r in scan.Ratings)
            _out.WriteLine($"  {r.Area.Label(),-34} {r.Grade}  {(r.NotAssessed ? "not assessed: " + r.NotAssessedReason : $"{r.Score}/100  {r.ScopeSummary}{(r.CapReason is null ? "" : "  [cap: " + r.CapReason + "]")}")}");
        _out.WriteLine($"Findings: {scan.Findings.Count} (High {scan.Findings.Count(f => f.Severity == "High")}, Medium {scan.Findings.Count(f => f.Severity == "Medium")}, Low {scan.Findings.Count(f => f.Severity == "Low")})");
        foreach (var g in scan.Findings.GroupBy(f => (f.Area, f.Category)).OrderBy(g => g.First().Priority).ThenBy(g => g.Key.Area))
            _out.WriteLine($"  P{g.First().Priority} {g.Key.Area.ShortLabel(),-10} {g.Key.Category} × {g.Count()}");
        foreach (var w in scan.Warnings) _out.WriteLine("WARNING: " + w);
        foreach (var i in scan.Issues)
            _out.WriteLine($"ISSUE [{i.Area.ShortLabel()}] {i.Source}: {i.Reason}. Needs {i.Needs}. {i.Impact}   FIX: {i.Fix}");

        Assert.Equal(6, scan.Ratings.Count);
        var html = AuditReportService.Html(new AuditReportContext { Scan = scan, CustomerName = target.DisplayName }, ReportKind.Plan);
        Assert.Contains("Improvement Plan", html);
    }
}
